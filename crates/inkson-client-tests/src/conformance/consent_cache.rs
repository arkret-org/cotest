//! The Consent fixture consumes actual Station cuts and the Native product path.
use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::call_invitation::*;
use arkret_models_collaboration::call_signal::*;
use arkret_models_collaboration::consent_operations::{
    ConsentGrantRequestBody, ConsentRevokeRequestBody, ConsentView,
};
use arkret_models_collaboration::events_payloads::consent::{ConsentGrantPayload, ConsentPeer};
use arkret_models_collaboration::governance_payloads::ConsentRevokePayload;
use arkret_models_collaboration::objects::media::{
    CallMediaDesiredMedia, CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody,
};
use arkret_wire::{CallId, ConsentScope, Event, EventAdmissionSubmission, EventKind, ScopeRef};
use chrono::{Duration, Utc};
use cotest::harness::{expect_json, next_typed_id};
use cotest::scenarios::consent_call_context::ConsentCallContext;
use cotest::scenarios::mls_lifecycle_live::Member;
use reqwest::StatusCode;

pub const CONSENT_CACHE_ENTRYPOINT: &str = "ak.suite.consent.cache_invalidation.v1";
const SFU_API_KEY: &str = "consent-2141-owned-test";
const SFU_API_SECRET: &str = "2141-owned-loopback-test-secret-with-more-than-32-characters";

async fn grant(
    context: &ConsentCallContext,
    holder: &Member,
    scope: ConsentScope,
    not_before: Option<chrono::DateTime<Utc>>,
    expires_at: Option<chrono::DateTime<Utc>>,
    constraints: Option<Vec<std::collections::BTreeMap<String, serde_json::Value>>>,
) -> Result<(ConsentView, Event)> {
    let principal = holder
        .client
        .principal
        .as_ref()
        .context("real holder PCR")?;
    let event = holder
        .client
        .author_event(
            principal.pcr_realm_id.as_str(),
            EventKind::ConsentGrant.as_str(),
            serde_json::to_value(ConsentGrantPayload {
                consent_id: arkret_wire::ConsentId::new(next_typed_id("consent"))?,
                peer: ConsentPeer::Actor {
                    actor_id: context.caller.actor.clone(),
                },
                consent_scope: scope,
                not_before,
                expires_at,
                constraints,
                evidence_ref: None,
                reason: None,
            })?,
        )
        .await?;
    let view = expect_json(
        holder
            .client
            .post("/_arkret/self/consent/results/grant")
            .json(&ConsentGrantRequestBody {
                grant_event: EventAdmissionSubmission::new(event.clone()),
            }),
        StatusCode::OK,
    )
    .await?;
    Ok((serde_json::from_value(view)?, event))
}

async fn revoke(holder: &Member, view: &ConsentView) -> Result<Event> {
    let principal = holder
        .client
        .principal
        .as_ref()
        .context("real holder PCR")?;
    let event = holder
        .client
        .author_event(
            principal.pcr_realm_id.as_str(),
            EventKind::ConsentRevoke.as_str(),
            serde_json::to_value(ConsentRevokePayload {
                consent_id: view.consent_id.clone(),
                expected_revision: view.revision.clone(),
                revoked_at: None,
                reason: None,
            })?,
        )
        .await?;
    expect_json(
        holder
            .client
            .post("/_arkret/self/consent/results/revoke")
            .json(&ConsentRevokeRequestBody {
                revoke_event: EventAdmissionSubmission::new(event.clone()),
            }),
        StatusCode::OK,
    )
    .await?;
    Ok(event)
}

async fn new_call(context: &ConsentCallContext) -> Result<CallId> {
    let event = context
        .caller
        .client
        .author_event(
            context.realm.as_str(),
            EventKind::CallCreate.as_str(),
            serde_json::json!({"initial_state":"ringing"}),
        )
        .await?;
    cotest::scenarios::human_device_producer_live::submit_and_expect_commit(
        &context.caller.client,
        &context.caller.account,
        context.caller.device.as_str(),
        &event,
    )
    .await?;
    let call = CallId::from_event_id(&event.event_id);
    let focus = context
        .caller
        .client
        .author_event(
            context.realm.as_str(),
            EventKind::CallState.as_str(),
            serde_json::json!({
                "call_id":call,"focus":{"mode":"sfu","session_focus":"consent-focus"}
            }),
        )
        .await?;
    cotest::scenarios::human_device_producer_live::submit_and_expect_commit(
        &context.caller.client,
        &context.caller.account,
        context.caller.device.as_str(),
        &focus,
    )
    .await?;
    eprintln!("[2141-live] accepted Call focus awaiting held replica");
    if let Err(error) = cotest::scenarios::human_device_producer_live::wait_for_committed(
        &context.holder.client,
        &focus.event_id,
    )
    .await
    {
        for (index, database) in context.databases.iter().enumerate().take(2) {
            let url = database.connect_url.clone();
            let realm = context.realm.to_string();
            let rows=tokio::task::spawn_blocking(move || ->Result<serde_json::Value> {
                let mut db=postgres::Client::connect(&url,postgres::NoTls)?;
                let row=db.query_one("SELECT jsonb_build_object('events',(SELECT jsonb_agg(jsonb_build_object('kind',envelope->>'kind','id',envelope->>'event_id','state',state)) FROM canonical_events WHERE realm_id=$1),'outbox',(SELECT jsonb_agg(jsonb_build_object('endpoint',endpoint,'state',state,'attempts',attempts,'status',last_http_status,'code',last_error_code,'response',left(last_response_excerpt,1000))) FROM federation_outbox))",&[&realm])?;
                Ok(row.get(0))
            }).await??;
            eprintln!("[2141-live] replica diagnostic Station {index}: {rows}");
        }
        return Err(error);
    }
    Ok(call)
}

async fn prepare_invitation(
    context: &mut ConsentCallContext,
    call: &CallId,
    holder: &arkret_wire::AccountId,
    media: CallInvitationMedia,
    sequence: u64,
) -> Result<CallInvitationSendRequestBody> {
    prepare_invitation_with_plaintext(context, call, holder, media, sequence, None).await
}

async fn prepare_invitation_with_plaintext(
    context: &mut ConsentCallContext,
    call: &CallId,
    holder: &arkret_wire::AccountId,
    media: CallInvitationMedia,
    sequence: u64,
    mutation: Option<u8>,
) -> Result<CallInvitationSendRequestBody> {
    let head = cotest::scenarios::websocket_live::realm_head(
        &context.caller.client,
        context.realm.as_str(),
    )
    .await?
    .commit_id;
    let plaintext=CallSignalPlaintext::new(sequence,call.clone(),sequence,CallSignalData::Invite(CallInviteSignalData {
        lifetime_ms:60_000,
        offer:SessionDescription{sdp_type:SessionDescriptionType::Offer,sdp:"v=0\r\no=- 2141 1 IN IP4 127.0.0.1\r\ns=Arkret conformance\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\na=sendrecv\r\n".to_owned()},
        media:CallMediaSelection{audio:media.audio,video:media.video,screen:Some(media.screen)},
    }))?;
    let plaintext = match mutation {
        Some(0) => CallSignalPlaintext::new(
            sequence,
            CallId::from_event_id(&context.accepted_group),
            sequence,
            plaintext.signal.clone(),
        )?,
        Some(1) => {
            let mut value = plaintext.clone();
            let CallSignalData::Invite(invite) = &mut value.signal else {
                unreachable!()
            };
            invite.media.video = !invite.media.video;
            value
        }
        Some(2) => CallSignalPlaintext::new(
            sequence,
            call.clone(),
            sequence,
            CallSignalData::Answer(CallAnswerSignalData {
                answer: SessionDescription {
                    sdp_type: SessionDescriptionType::Answer,
                    sdp: "v=0\r\no=- 2141 1 IN IP4 127.0.0.1\r\ns=answer\r\nt=0 0\r\n".to_owned(),
                },
                accepted_media: CallMediaSelection {
                    audio: media.audio,
                    video: media.video,
                    screen: Some(media.screen),
                },
            }),
        )?,
        None => plaintext,
        _ => anyhow::bail!("unknown actual plaintext mutation"),
    };
    let envelope = cotest::scenarios::signal_live::scoped_envelope_with_payload(
        &context.caller,
        &mut context.caller_group,
        &context.realm,
        "",
        &context.accepted_group,
        &head,
        arkret_wire::SignalClass::Setup,
        sequence,
        ScopeRef::Realm {
            realm_id: context.realm.clone(),
        },
        None,
        Some(arkret_models_collaboration::signal_plaintext::seal_signal_plaintext(&plaintext)?),
    )?;
    let mut invitation = CallInvitationEnvelope {
        inviter_actor_id: context.caller.actor.clone(),
        holder_account_id: holder.clone(),
        scope_ref: envelope.scope_ref.clone(),
        call_id: call.clone(),
        media,
        envelope_digest: canonical_request_digest(&envelope)?,
        expires_at: envelope.expires_at,
        proof: CallInvitationProof {
            verification_method: context.caller.method.to_string(),
            jws: String::new(),
        },
    };
    invitation.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        &context.caller.key,
        &invitation.signature_input()?,
    )?;
    invitation.validate_for_envelope(&envelope)?;
    Ok(CallInvitationSendRequestBody {
        invitation,
        envelope,
    })
}

async fn send(context: &ConsentCallContext, request: &CallInvitationSendRequestBody) -> Result<()> {
    let result: CallInvitationSendOutcome = serde_json::from_value(
        expect_json(
            context
                .caller
                .client
                .post("/_arkret/self/rtc/invitation")
                .json(request),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        result.status == CallInvitationSendStatus::Deferred,
        "sender received a holder-dependent result"
    );
    Ok(())
}

fn invited_token(
    context: &ConsentCallContext,
    request: &CallInvitationSendRequestBody,
    media: CallInvitationMedia,
) -> CallMediaTokenExchangeRequestBody {
    CallMediaTokenExchangeRequestBody {
        realm_id: context.realm.clone(),
        call_id: request.invitation.call_id.clone(),
        actor_id: context.holder.actor.clone(),
        device_id: context.holder.device.clone(),
        focus_id: "consent-focus".to_owned(),
        capability_refs: vec![],
        desired_media: Some(CallMediaDesiredMedia {
            audio: Some(media.audio),
            video: Some(media.video),
            screen: Some(media.screen),
        }),
        join_context: CallMediaJoinContext::Invitation(CallInvitationJoinContext {
            kind: CallInvitationJoinKind::Invitation,
            invitation: request.invitation.clone(),
            envelope: request.envelope.clone(),
        }),
    }
}

async fn ready_stream(holder: &Member) -> Result<arkret_http_client::SignalSubscribeFrameStream> {
    let mut stream = holder.client.sdk().signal_subscribe_frames().await?;
    let frame =
        tokio::time::timeout(std::time::Duration::from_secs(20), stream.next_frame()).await??;
    ensure!(
        matches!(
            frame,
            Some(arkret_models_collaboration::SignalStreamFrame::Heartbeat)
        ),
        "Signal subscription was not ready before target submission"
    );
    Ok(stream)
}

async fn exchange(
    holder: &Member,
    request: &CallMediaTokenExchangeRequestBody,
) -> Result<CallMediaTokenExchangeOutcome> {
    Ok(serde_json::from_value(
        expect_json(
            holder.client.post("/_arkret/self/rtc/token").json(request),
            StatusCode::OK,
        )
        .await?,
    )?)
}

async fn install_media(context: &ConsentCallContext, kind: &str, connect: &str) -> Result<()> {
    let value: arkret_models_collaboration::events_payloads::RealmMediaServiceValue =
        serde_json::from_value(serde_json::json!({
            "service_id":context.stations.server(1).service_id(),"foci":[{"focus_id":"consent-focus","focus_kind":kind,
            "token_endpoint":context.stations.server(1).url("/_arkret/self/rtc/token"),"connect_url":connect}],
            "default_call_mode":"sfu","allowed_call_modes":["sfu"]
        }))?;
    value.validate()?;
    let event = context
        .caller
        .client
        .author_event(
            context.realm.as_str(),
            EventKind::RealmMediaService.as_str(),
            serde_json::json!({"value":value}),
        )
        .await?;
    cotest::scenarios::human_device_producer_live::submit_and_expect_commit(
        &context.caller.client,
        &context.caller.account,
        context.caller.device.as_str(),
        &event,
    )
    .await?;
    cotest::scenarios::human_device_producer_live::wait_for_committed(
        &context.holder.client,
        &event.event_id,
    )
    .await?;
    Ok(())
}

async fn verify_token(
    context: &ConsentCallContext,
    request: &CallMediaTokenExchangeRequestBody,
    outcome: &CallMediaTokenExchangeOutcome,
) -> Result<()> {
    let station = context.stations.server(1);
    let member = [&context.holder, &context.denied_holder, &context.caller]
        .into_iter()
        .find(|member| request.actor_id.as_account_id() == Some(&member.account))
        .context("exact actual media subject")?;
    let binding = inkson::media::service_route::binding_for_http(
        &member.client.sdk(),
        &context.realm,
        station.service_id(),
    )
    .await?;
    ensure!(
        binding.value()?.route.service_kind == "station",
        "Station issuer was relabelled as media_service"
    );
    let anchors = inkson::media::rtc::verified_binding_anchors(
        &member.account,
        &context.realm,
        &[station.service_id().clone()],
        &[binding],
    )
    .map_err(|e| anyhow::anyhow!("production media binding anchors: {e:?}"))?;
    arkret_signatures::media::verify_call_media_token_outcome(
        request,
        outcome,
        &anchors,
        Utc::now(),
    )?;
    ensure!(outcome.actor_id == request.actor_id && outcome.device_id == request.device_id);
    ensure!(
        outcome.roster_identity.actor_id
            != request
                .actor_id
                .as_account_id()
                .context("media subject Account")?
                .principal_id
            && outcome.roster_identity.device_id != request.device_id
    );
    Ok(())
}

async fn excluded_discovery(context: &ConsentCallContext) -> Result<()> {
    let station = context.stations.server(1);
    let index_state = |url: String| async move {
        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let mut db=postgres::Client::connect(&url,postgres::NoTls)?;
            Ok(db.query("SELECT tablename FROM pg_tables WHERE schemaname='public' AND (tablename ILIKE '%psi%' OR tablename ILIKE '%discovery%') ORDER BY tablename",&[])?.into_iter().map(|r|r.get(0)).collect())
        }).await?
    };
    let before = index_state(context.databases[1].connect_url.clone()).await?;
    ensure!(
        before.is_empty(),
        "excluded private discovery has a persistent index"
    );
    let description: arkret::ServiceDescribe = station
        .http()
        .get(station.url("/_arkret/describe"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let description = serde_json::to_string(&description)?;
    for excluded in [
        "privateDiscovery",
        "private_discovery",
        "psi.query",
        "psi.rotate",
    ] {
        ensure!(
            !description.contains(excluded),
            "excluded operation advertised: {excluded}"
        );
    }
    for path in [
        "/_arkret/self/contacts/privateDiscovery",
        "/_arkret/self/contacts/private-discovery",
        "/_arkret/self/psi/query",
        "/_arkret/peer/psi/rotate",
    ] {
        let response = context
            .holder
            .client
            .post(path)
            .json(&serde_json::json!({}))
            .send()
            .await?;
        ensure!(
            matches!(
                response.status(),
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED | StatusCode::GONE
            ),
            "excluded operation did not prove route unavailability: {path} {}",
            response.status()
        );
    }
    let directory: serde_json::Value = station
        .http()
        .get(station.url("/_arkret/open/mimi/provider-directory"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let provider = directory
        .pointer("/mimi/provider_id")
        .and_then(serde_json::Value::as_str)
        .context("actual MIMI provider")?;
    let body: arkret_models_collaboration::mimi_operations::MimiIdentifierQueryRequestBody =
        serde_json::from_value(
            serde_json::json!({"identifiers":(["mimi_uri","did","handle","phone","email","opaque"].iter().map(|kind|serde_json::json!({"kind":kind,"identifier_commitment":arkret_canonical::sha256_digest(kind.as_bytes())})).collect::<Vec<_>>())}),
        )?;
    let (status, value) =
        cotest::scenarios::mimi_facade_live::signed_identifier_query(station, provider, &body)
            .await?;
    ensure!(
        status == StatusCode::OK,
        "authenticated MIMI identifiers failed: {status} {value}"
    );
    let matches = value["matches"].as_array().context("MIMI match results")?;
    ensure!(
        matches.len() == 6
            && matches.iter().all(|r| r["matched"] == false
                && r.get("mimi_uri").is_none()
                && r.get("subject_id").is_none()
                && r.get("handoff").is_none()),
        "MIMI commitment revealed an identity"
    );
    ensure!(
        index_state(context.databases[1].connect_url.clone()).await? == before,
        "excluded attempts changed indexes"
    );
    Ok(())
}

async fn private_release_state(context: &ConsentCallContext) -> Result<Vec<String>> {
    let url = context.databases[1].connect_url.clone();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        // Compare privately in memory; never log subject mappings or receipts.
        ["call_media_subject_identities", "call_voluntary_join_nonces"].into_iter()
            .map(|table| Ok(db.query_one(&format!(
                "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM {table} t"
            ), &[])?.get::<_,String>(0))).collect()
    }).await?
}

async fn reject_token(
    context: &ConsentCallContext,
    holder: &Member,
    request: &CallMediaTokenExchangeRequestBody,
) -> Result<()> {
    let before = private_release_state(context).await?;
    let response = holder
        .client
        .post("/_arkret/self/rtc/token")
        .json(request)
        .send()
        .await?;
    ensure!(
        !response.status().is_success(),
        "unauthorized token was released"
    );
    let problem: serde_json::Value = response.json().await?;
    ensure!(
        problem.get("backend_token").is_none(),
        "refusal carried media credentials"
    );
    ensure!(
        private_release_state(context).await? == before,
        "refused token changed private identity or voluntary nonce storage"
    );
    Ok(())
}

async fn accept_roster(
    context: &ConsentCallContext,
    holder: &Member,
    outcome: &CallMediaTokenExchangeOutcome,
) -> Result<Event> {
    let event=holder.client.author_event(context.realm.as_str(),EventKind::CallState.as_str(),serde_json::json!({
        "call_id":outcome.call_id,"roster_delta":{"op":"join","participant":{
            "actor_id":outcome.roster_identity.actor_id,"device_id":outcome.roster_identity.device_id,
            "joined_at":arkret_canonical::format_timestamp_canonical(chrono::DateTime::<Utc>::from_timestamp(Utc::now().timestamp().div_euclid(300)*300,0).unwrap()),
            "media":outcome.subject_binding.media,"focus_id":outcome.focus_id,
            "participant_id":outcome.participant_id,"participant_binding":outcome.participant_binding
        }}
    })).await?;
    ensure!(
        arkret_signatures::media::VerifiedCallParticipant::verify(
            &event,
            context.stations.server(1).service_id(),
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: context
                    .stations
                    .server(1)
                    .federation_signing_key()?
                    .verifying_key()
                    .to_bytes()
                    .to_vec()
            }
        )?
        .is_some(),
        "actual public roster tuple differs from the original signed token"
    );
    cotest::scenarios::human_device_producer_live::submit_and_expect_commit(
        &holder.client,
        &holder.account,
        holder.device.as_str(),
        &event,
    )
    .await?;
    Ok(event)
}

fn refresh(
    request: &CallMediaTokenExchangeRequestBody,
    outcome: &CallMediaTokenExchangeOutcome,
) -> CallMediaTokenExchangeRequestBody {
    let mut request = request.clone();
    request.join_context = CallMediaJoinContext::Refresh(CallRefreshJoinContext {
        kind: CallRefreshJoinKind::Refresh,
        participant_id: outcome.participant_id.clone(),
        subject_binding: outcome.subject_binding.clone(),
    });
    request
}

fn voluntary(
    holder: &Member,
    request: &CallMediaTokenExchangeRequestBody,
    sequence: u8,
) -> Result<CallMediaTokenExchangeRequestBody> {
    let mut request = request.clone();
    let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    request.join_context = CallMediaJoinContext::Voluntary(CallVoluntaryJoinContext {
        kind: CallVoluntaryJoinKind::Voluntary,
        created_at: now,
        expires_at: now + Duration::seconds(60),
        nonce: arkret_canonical::base64url_encode([sequence; 32]),
        proof: CallVoluntaryJoinProof {
            verification_method: holder.method.to_string(),
            jws: String::new(),
        },
    });
    let input =
        arkret_models_collaboration::call_invitation::voluntary_join_signing_input_from_value(
            &serde_json::to_value(&request)?,
        )?;
    let CallMediaJoinContext::Voluntary(intent) = &mut request.join_context else {
        unreachable!()
    };
    intent.proof.jws = arkret_signatures::sign_ed25519_detached_jws(&holder.key, &input)?;
    Ok(request)
}

/// Run the actual Station, Native and SFU cuts without certifying absent obligations.
pub async fn run_three_cuts_live() -> Result<()> {
    run_three_cuts_evidence().await.map(|_| ())
}

/// Isolate the actual current-based sender and cold RTC boundaries for regression diagnosis.
pub async fn run_presence_and_media_cuts_live() -> Result<()> {
    let env = [
        ("COLAND_LIVEKIT_API_KEY".into(), SFU_API_KEY.into()),
        ("COLAND_LIVEKIT_API_SECRET".into(), SFU_API_SECRET.into()),
    ];
    let context = cotest::harness::heap_future(|| async {
        ConsentCallContext::create("consent-media-current", &env)
            .await
            .map(Box::new)
    })
    .await?;
    install_media(
        &context,
        "arkret_native",
        "https://media.consent.invalid/connect",
    )
    .await?;
    let directory = tempfile::tempdir()?;
    let holder_path = directory.path().join("holder.json");
    let other_path = directory.path().join("other.json");
    let native = cotest::harness::heap_future(|| async {
        super::account_blocklist_projection::native_signal_endpoint(
            &context.holder,
            &context.realm,
            &context.accepted_group,
            &context.holder_group,
            &holder_path,
        )
        .await
        .map(Box::new)
    })
    .await?;
    let other = cotest::harness::heap_future(|| async {
        super::account_blocklist_projection::native_signal_endpoint(
            &context.denied_holder,
            &context.realm,
            &context.accepted_group,
            &context.denied_group,
            &other_path,
        )
        .await
        .map(Box::new)
    })
    .await?;
    cotest::harness::heap_future(|| presence_current(&context, &native, &directory)).await?;
    let sequence = 1;
    let (context, native, other, _sequence) = media_phase(context, native, other, sequence).await?;
    drop((context, native, other));
    cotest::harness::heap_future(run_authority_change_live).await?;
    Ok(())
}

async fn run_three_cuts_evidence() -> Result<Vec<super::CaseExecutionResult>> {
    let mut evidence = Vec::new();
    eprintln!("[2141-live] actual three-Station context start");
    let emission_probe = tempfile::tempdir()?;
    let pause_file = emission_probe.path().join("consent-emission.pause");
    let holder_env = [
        ("COLAND_LIVEKIT_API_KEY".into(), SFU_API_KEY.into()),
        ("COLAND_LIVEKIT_API_SECRET".into(), SFU_API_SECRET.into()),
        (
            "COLAND_CONFORMANCE_SIGNAL_EMISSION_PAUSE_FILE".into(),
            pause_file.to_string_lossy().into_owned(),
        ),
    ];
    let mut context = cotest::harness::heap_future(|| async {
        ConsentCallContext::create("consent-three-cuts", &holder_env)
            .await
            .map(Box::new)
    })
    .await?;
    eprintln!("[2141-live] actual accepted membership and MLS source ready");
    install_media(
        &context,
        "arkret_native",
        "https://media.consent.invalid/connect",
    )
    .await?;
    excluded_discovery(&context).await?;
    completed_case(&mut evidence, 0, 3)?;
    let call = new_call(&context).await?;
    let (voice_grant, voice_event) = grant(
        &context,
        &context.holder,
        ConsentScope::VoiceCall,
        None,
        None,
        None,
    )
    .await?;
    let directory = tempfile::tempdir()?;
    let native = cotest::harness::heap_future(|| async {
        super::account_blocklist_projection::native_signal_endpoint(
            &context.holder,
            &context.realm,
            &context.accepted_group,
            &context.holder_group,
            &directory.path().join("holder.json"),
        )
        .await
        .map(Box::new)
    })
    .await?;
    eprintln!("[2141-live] actual Native current baseline ready");
    let holder = context.holder.account.clone();
    let request = prepare_invitation(
        &mut context,
        &call,
        &holder,
        CallInvitationMedia {
            audio: true,
            video: false,
            screen: false,
        },
        1,
    )
    .await?;
    let mut stream = ready_stream(&context.holder).await?;
    send(&context, &request).await?;
    let mut receiver = garth::signal::SignalReceiver::new();
    let received = super::account_blocklist_projection::next_admitted_signal(
        &mut stream,
        &native,
        &context.holder,
        &mut receiver,
    )
    .await?;
    let garth::signal::SignalReceiveOutcome::Accepted {
        call_invitation: Some(_),
        ..
    } = &received
    else {
        anyhow::bail!("actual subscriber lacked holder product material");
    };
    let admitted = format!("{received:?}");
    let rings = inkson::conformance::observe_native_call_projection(&native, received).await?;
    if rings != 1 {
        return Err(cotest::harness::heap_future(|| {
            call_projection_failure(
                &context,
                &native,
                &request,
                admitted,
                "actual Native product cut did not release the lawful Invite".to_owned(),
            )
        })
        .await);
    }
    let token = invited_token(
        &context,
        &request,
        CallInvitationMedia {
            audio: true,
            video: false,
            screen: false,
        },
    );
    let outcome = exchange(&context.holder, &token).await?;
    verify_token(&context, &token, &outcome).await?;
    reject_token(&context, &context.holder, &refresh(&token, &outcome)).await?;
    let mut expansion = token.clone();
    expansion.desired_media.as_mut().unwrap().video = Some(true);
    reject_token(&context, &context.holder, &expansion).await?;
    let roster = accept_roster(&context, &context.holder, &outcome).await?;
    ensure!(
        serde_json::to_value(&roster.payload)?.pointer("/roster_delta/participant/actor_id")
            == Some(&serde_json::json!(outcome.roster_identity.actor_id))
    );
    let refreshed = exchange(&context.holder, &refresh(&token, &outcome)).await?;
    verify_token(&context, &refresh(&token, &outcome), &refreshed).await?;
    ensure!(
        refreshed.roster_identity == outcome.roster_identity
            && refreshed.participant_id == outcome.participant_id
    );
    let old_read = inkson::conformance::read_native_consent_current(
        &native,
        context.caller.actor.clone(),
        ConsentScope::VoiceCall,
    )
    .await?;
    ensure!(inkson::conformance::consume_native_consent_current(&native, &old_read).await?);
    let exact_revoke = revoke(&context.holder, &voice_grant).await?;
    let revoke_footprint = consent_commit_count(&context).await?;
    let replayed: ConsentView = serde_json::from_value(
        expect_json(
            context
                .holder
                .client
                .post("/_arkret/self/consent/results/revoke")
                .json(&ConsentRevokeRequestBody {
                    revoke_event: EventAdmissionSubmission::new(exact_revoke),
                }),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        replayed.state == arkret_models_collaboration::consent_operations::ConsentState::Revoked,
        "exact Revoke retry lost original outcome"
    );
    let revoked_read = inkson::conformance::read_native_consent_current(
        &native,
        context.caller.actor.clone(),
        ConsentScope::VoiceCall,
    )
    .await?;
    ensure!(!inkson::conformance::consume_native_consent_current(&native, &revoked_read).await?);
    ensure!(
        inkson::conformance::consume_native_consent_current(&native, &old_read)
            .await
            .is_err()
    );
    reject_token(&context, &context.holder, &token).await?;
    let after_revoke = exchange(&context.holder, &refresh(&token, &outcome)).await?;
    verify_token(&context, &refresh(&token, &outcome), &after_revoke).await?;
    let voluntary = voluntary(&context.holder, &token, 0x93)?;
    let voluntary_outcome = exchange(&context.holder, &voluntary).await?;
    verify_token(&context, &voluntary, &voluntary_outcome).await?;
    reject_token(&context, &context.holder, &voluntary).await?;
    let retried: ConsentView = serde_json::from_value(
        expect_json(
            context
                .holder
                .client
                .post("/_arkret/self/consent/results/grant")
                .json(&ConsentGrantRequestBody {
                    grant_event: EventAdmissionSubmission::new(voice_event),
                }),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        retried == voice_grant,
        "exact grant replay changed its original result"
    );
    let latest = inkson::conformance::read_native_consent_current(
        &native,
        context.caller.actor.clone(),
        ConsentScope::VoiceCall,
    )
    .await?;
    ensure!(
        latest
            .value()?
            .consents
            .iter()
            .find(|r| r.value.consent_id == voice_grant.consent_id)
            .context("revoked current")?
            .revision
            == revoked_read
                .value()?
                .consents
                .iter()
                .find(|r| r.value.consent_id == voice_grant.consent_id)
                .context("revoke revision")?
                .revision
    );
    cotest::harness::heap_future(|| {
        private_refresh_matrix(&mut context, &token, &outcome, &refreshed)
    })
    .await?;
    ensure!(
        consent_commit_count(&context).await? == revoke_footprint,
        "exact Grant/Revoke retry added a PCR Commit"
    );
    completed_case(&mut evidence, 3, 5)?;
    let mut sequence = 2;
    cotest::harness::heap_future(|| {
        queued_revoke(&mut context, &native, &pause_file, &mut sequence)
    })
    .await?;
    opaque_response(&mut context, &mut sequence).await?;
    completed_case(&mut evidence, 4, 3)?;
    relation_mutations(&mut context, &native, &mut sequence).await?;
    completed_case(&mut evidence, 7, 13)?;
    independent_windows(&mut context, &native, &mut sequence).await?;
    completed_case(&mut evidence, 9, 6)?;
    let denied_native = cotest::harness::heap_future(|| async {
        super::account_blocklist_projection::native_signal_endpoint(
            &context.denied_holder,
            &context.realm,
            &context.accepted_group,
            &context.denied_group,
            &directory.path().join("denied-holder.json"),
        )
        .await
        .map(Box::new)
    })
    .await?;
    independent_holders(&mut context, &native, &denied_native, &mut sequence).await?;
    completed_case(&mut evidence, 6, 1)?;
    completed_case(&mut evidence, 8, 4)?;
    cotest::harness::heap_future(|| presence_current(&context, &native, &directory)).await?;
    completed_case(&mut evidence, 2, 9)?;
    let (context, native, denied_native, _sequence) =
        media_phase(context, native, denied_native, sequence).await?;
    completed_case(&mut evidence, 5, 6)?;
    completed_case(&mut evidence, 10, 8)?;
    completed_case(&mut evidence, 12, 21)?;
    drop((context, native, denied_native));
    cotest::harness::heap_future(run_authority_change_live).await?;
    completed_case(&mut evidence, 13, 5)?;
    Ok(evidence)
}

async fn product_attempt(
    context: &ConsentCallContext,
    member: &Member,
    native: &inkson::sync_engine::NativeAccountHost,
    request: &CallInvitationSendRequestBody,
    dedicated: bool,
) -> Result<usize> {
    native
        .catch_up_selected_realm_until_complete(&context.realm)
        .await?;
    product_attempt_after_current(context, member, native, request, dedicated).await
}

#[inline(never)]
fn product_attempt_after_current<'a>(
    context: &'a ConsentCallContext,
    member: &'a Member,
    native: &'a inkson::sync_engine::NativeAccountHost,
    request: &'a CallInvitationSendRequestBody,
    dedicated: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize>> + 'a>> {
    cotest::harness::heap_future(move || async move {
        let mut stream = ready_stream(member).await?;
        if dedicated {
            send(context, request).await?;
        } else {
            let accepted = context
                .caller
                .client
                .sdk()
                .signal_send(&request.envelope)
                .await?;
            ensure!(
                accepted.accepted,
                "ordinary encrypted rail refused the legal source"
            );
        }
        let mut receiver = garth::signal::SignalReceiver::new();
        let started = std::time::Instant::now();
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            super::account_blocklist_projection::next_admitted_signal(
                &mut stream,
                native,
                member,
                &mut receiver,
            ),
        )
        .await;
        let received = match received {
            Ok(Err(error))
                if [
                    "call invitation delivery contains another plaintext kind",
                    "call invitation plaintext is not Invite",
                    "call invitation plaintext differs from signed relation",
                ]
                .iter()
                .any(|reason| error.to_string().contains(reason)) =>
            {
                return Ok(0);
            }
            Ok(result) => result?,
            Err(_) => {
                eprintln!(
                    "[2141-product] received=false dedicated={dedicated} elapsed_ms={}",
                    started.elapsed().as_millis()
                );
                return Ok(0);
            }
        };
        if let garth::signal::SignalReceiveOutcome::Accepted {
            call_invitation,
            plaintext,
            effective_expires_at,
            ..
        } = &received
        {
            let call_matches = matches!(plaintext.as_ref(), arkret::SignalPlaintext::CallSignal(call)
            if call.call_id == request.invitation.call_id);
            let product_live = call_invitation
                .as_ref()
                .is_some_and(|view| view.outcome.expires_at > Utc::now());
            let current = inkson::conformance::retained_realm_current(
                &native.state_store(),
                &member.account,
                &context.realm,
            )
            .await?;
            let rows: Vec<arkret_wire::TypedCurrentRow> =
                serde_json::from_value(current["entries"].clone())?;
            let installed = rows.iter().any(|row| matches!(row,
            arkret_wire::TypedCurrentRow::Value {selector: arkret_wire::CurrentSelector::CallState {call_id}, ..}
                if call_id == &request.invitation.call_id));
            eprintln!(
                "[2141-product] received=true dedicated={dedicated} exact_call={call_matches} product={} product_live={product_live} signal_live={} call_current_installed={installed} elapsed_ms={}",
                call_invitation.is_some(),
                effective_expires_at > &Utc::now(),
                started.elapsed().as_millis()
            );
        }
        let projected =
            inkson::conformance::observe_native_call_projection(native, received).await?;
        if dedicated && projected == 0 {
            let read =
                inkson::conformance::read_native_call_consent(native, &request.invitation).await;
            let read_ok = read.is_ok();
            let permitted =
                read.and_then(|value| value.permits(None, &[], Utc::now()).map_err(Into::into));
            eprintln!(
                "[2141-product] projected=0 fresh_current_read={read_ok} fresh_current_allowed={}",
                permitted.is_ok_and(|value| value)
            );
        }
        Ok(projected)
    })
}

// Poll the actual media fixture as its own task, after the parent driver
// returns Pending. The services, native hosts and MLS material remain owned
// across the join; nested large debug poll frames do not share one stack.
fn media_phase(
    mut context: Box<ConsentCallContext>,
    native: Box<inkson::sync_engine::NativeAccountHost>,
    other: Box<inkson::sync_engine::NativeAccountHost>,
    mut sequence: u64,
) -> impl std::future::Future<
    Output = Result<(
        Box<ConsentCallContext>,
        Box<inkson::sync_engine::NativeAccountHost>,
        Box<inkson::sync_engine::NativeAccountHost>,
        u64,
    )>,
> {
    let task = tokio::task::spawn_local(cotest::harness::heap_future(move || async move {
        cotest::harness::heap_future(|| sfu_media(&mut context, &native, &other, &mut sequence))
            .await?;
        Ok((context, native, other, sequence))
    }));
    async move { task.await.context("actual media fixture task failed")? }
}

async fn sfu_media(
    context: &mut ConsentCallContext,
    holder_native: &inkson::sync_engine::NativeAccountHost,
    denied_native: &inkson::sync_engine::NativeAccountHost,
    sequence: &mut u64,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let connect = format!("wss://127.0.0.1:{port}");
    install_media(context, "livekit", &connect).await?;
    let (holder_grant, _) = grant(
        context,
        &context.holder,
        ConsentScope::VideoCall,
        None,
        None,
        None,
    )
    .await?;
    let (peer_grant, _) = grant(
        context,
        &context.denied_holder,
        ConsentScope::VideoCall,
        None,
        None,
        None,
    )
    .await?;
    let call = new_call(context).await?;
    let media = CallInvitationMedia {
        audio: true,
        video: true,
        screen: false,
    };
    let holder = context.holder.account.clone();
    let holder_invite =
        prepare_invitation(context, &call, &holder, media.clone(), *sequence).await?;
    *sequence += 1;
    let peer = context.denied_holder.account.clone();
    let peer_invite = prepare_invitation(context, &call, &peer, media.clone(), *sequence).await?;
    *sequence += 1;
    ensure!(
        product_attempt(
            context,
            &context.holder,
            holder_native,
            &holder_invite,
            true
        )
        .await?
            == 1
    );
    ensure!(
        product_attempt(
            context,
            &context.denied_holder,
            denied_native,
            &peer_invite,
            true
        )
        .await?
            == 1
    );
    let holder_token = invited_token(context, &holder_invite, media.clone());
    let mut peer_token = invited_token(context, &peer_invite, media);
    peer_token.actor_id = context.denied_holder.actor.clone();
    peer_token.device_id = context.denied_holder.device.clone();
    let holder_outcome = exchange(&context.holder, &holder_token).await?;
    let peer_outcome = exchange(&context.denied_holder, &peer_token).await?;
    verify_token(context, &holder_token, &holder_outcome).await?;
    verify_token(context, &peer_token, &peer_outcome).await?;
    accept_roster(context, &context.holder, &holder_outcome).await?;
    accept_roster(context, &context.denied_holder, &peer_outcome).await?;
    let mut native_sessions = Vec::new();
    for (host, member, request, accepted) in [
        (
            holder_native,
            &context.holder,
            &holder_token,
            &holder_outcome,
        ),
        (
            denied_native,
            &context.denied_holder,
            &peer_token,
            &peer_outcome,
        ),
    ] {
        host.catch_up_selected_realm_until_complete(&context.realm)
            .await?;
        let session = inkson::conformance::join_native_call_media(
            host,
            member.client.sdk(),
            &refresh(request, accepted),
            context.stations.server(1).service_id(),
        )
        .await?;
        let event=member.client.author_event(context.realm.as_str(),EventKind::CallState.as_str(),serde_json::json!({
            "call_id":request.call_id,"roster_delta":{"op":"join","participant":{
                "actor_id":session.roster_identity.actor_id,"device_id":session.roster_identity.device_id,
                "focus_id":session.focus_id,"participant_id":session.participant_id,
                "participant_binding":session.participant_binding,"media":session.subject_binding.media
            }}
        })).await?;
        cotest::scenarios::human_device_producer_live::submit_and_expect_commit(
            &member.client,
            &member.account,
            member.device.as_str(),
            &event,
        )
        .await?;
        inkson::media::rtc::persist_accepted_media_receipt(&session).await?;
        let restored = inkson::media::rtc::restore_refresh_context(
            &member.account,
            &member.device,
            &context.realm,
            &request.call_id,
            &session.participant_binding.subject_binding_digest,
        )?
        .context("cold private receipt restore")?;
        let mut cold_refresh = request.clone();
        cold_refresh.join_context = restored;
        verify_token(
            context,
            &cold_refresh,
            &exchange(member, &cold_refresh).await?,
        )
        .await?;
        let mut other = member.account.clone();
        other.station_id = context.stations.server(2).service_id().clone();
        ensure!(
            inkson::media::rtc::restore_refresh_context(
                &other,
                &member.device,
                &context.realm,
                &request.call_id,
                &session.participant_binding.subject_binding_digest
            )?
            .is_none(),
            "another full Account restored the private receipt"
        );
        ensure!(
            inkson::media::rtc::restore_refresh_context(
                &member.account,
                &member.device,
                &context.realm,
                &request.call_id,
                "sha256:unaccepted"
            )?
            .is_none(),
            "another public commitment restored the private receipt"
        );
        // A new host instance restores the durable current index and private MLS checkpoint.
        let mut store = host.state_store();
        let reopened = store.conformance_reopen();
        let mut local = store.load();
        local.raw_operations.clear();
        store.save(local);
        let cold = inkson::sync_engine::NativeAccountHost::new_for_realm(
            member.client.sdk(),
            member.account.clone(),
            member.device.clone(),
            reopened,
            context.realm.clone(),
        )
        .await?;
        cold.catch_up_selected_realm_until_complete(&context.realm)
            .await?;
        ensure!(
            cold.state_store().load().raw_operations.is_empty(),
            "cold media current unexpectedly needed raw Event history"
        );
        let cold_session = inkson::conformance::join_native_call_media(
            &cold,
            member.client.sdk(),
            &cold_refresh,
            context.stations.server(1).service_id(),
        )
        .await?;
        ensure!(
            cold_session.frame_key == session.frame_key,
            "MLS checkpoint restore changed sender frame key"
        );
        native_sessions.push((session, cold_refresh));
    }
    let tokens: Vec<_> = native_sessions
        .iter()
        .map(|(session, _)| session.backend_token.clone())
        .collect();
    let frame_keys: Vec<_> = native_sessions.iter().map(|(session,_)| serde_json::json!({"participant_id":session.participant_id,"key":arkret_canonical::base64url_encode(session.frame_key.as_slice())})).collect();
    let python = std::env::var("COLAND_TEST_SFU_PYTHON")
        .context("real SFU Python RTC runtime is required")?;
    let server =
        std::env::var("COLAND_TEST_LIVEKIT_BIN").context("actual LiveKit server is required")?;
    let mut child = tokio::process::Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/consent_sfu_probe.py"
        ))
        .env("LIVEKIT_LOG_LEVEL", "error")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().context("owned SFU probe stdin")?;
    let mut output =
        tokio::io::BufReader::new(child.stdout.take().context("owned SFU probe stdout")?).lines();
    let data = serde_json::json!({"port":port,"api_key":SFU_API_KEY,"api_secret":SFU_API_SECRET,"tokens":tokens,"frame_keys":frame_keys,"livekit_bin":server});
    input.write_all(&serde_json::to_vec(&data)?).await?;
    input.write_all(b"\n").await?;
    input.flush().await?;
    let checked: Result<()> = async {
        let line = tokio::time::timeout(std::time::Duration::from_secs(40), output.next_line())
            .await??
            .context("owned SFU ended before connection proof")?;
        let status: serde_json::Value = serde_json::from_str(&line)?;
        ensure!(
            status["phase"] == "connected" && status["actual_audio_video_frames"] == true,
            "actual SFU media was not observed"
        );
        revoke(&context.holder, &holder_grant).await?;
        revoke(&context.denied_holder, &peer_grant).await?;
        reject_token(context, &context.holder, &holder_token).await?;
        reject_token(context, &context.denied_holder, &peer_token).await?;
        for (member, (_, refresh)) in [&context.holder, &context.denied_holder]
            .into_iter()
            .zip(&native_sessions)
        {
            verify_token(context, refresh, &exchange(member, refresh).await?).await?;
        }
        input
            .write_all(b"{\"phase\":\"consent_revoked\"}\n")
            .await?;
        input.flush().await?;
        let line = tokio::time::timeout(std::time::Duration::from_secs(10), output.next_line())
            .await??
            .context("owned SFU ended before established-session proof")?;
        let status: serde_json::Value = serde_json::from_str(&line)?;
        ensure!(
            status["phase"] == "complete" && status["media_survived_revoke"] == true,
            "Consent revoke interrupted established media"
        );
        Ok(())
    }
    .await;
    drop(input);
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait()).await??;
    checked?;
    ensure!(status.success(), "actual SFU probe failed");
    eprintln!(
        "[2141-live] actual_native_rtc_joins=2 cold_current_without_raw_history=2 durable_private_receipt_restore=2 mls_sender_frame_keys=2 actual_http_tokens=2 anonymous_sfu_publishers=2 actual_audio_video_frames=1 established_media_survived_revoke=1 loopback_sfu_transport=1"
    );
    Ok(())
}

async fn independent_holders(
    context: &mut ConsentCallContext,
    holder_native: &inkson::sync_engine::NativeAccountHost,
    denied_native: &inkson::sync_engine::NativeAccountHost,
    sequence: &mut u64,
) -> Result<()> {
    let (permission, _) = grant(
        context,
        &context.holder,
        ConsentScope::VoiceCall,
        None,
        None,
        None,
    )
    .await?;
    let call = new_call(context).await?;
    let media = CallInvitationMedia {
        audio: true,
        video: false,
        screen: false,
    };
    let holder = context.holder.account.clone();
    let allowed = prepare_invitation(context, &call, &holder, media.clone(), *sequence).await?;
    *sequence += 1;
    ensure!(product_attempt(context, &context.holder, holder_native, &allowed, true).await? == 1);
    let token = invited_token(context, &allowed, media.clone());
    let outcome = exchange(&context.holder, &token).await?;
    verify_token(context, &token, &outcome).await?;
    let ordinary_call = new_call(context).await?;
    let ordinary =
        prepare_invitation(context, &ordinary_call, &holder, media.clone(), *sequence).await?;
    *sequence += 1;
    ensure!(
        product_attempt(context, &context.holder, holder_native, &ordinary, false).await? == 0,
        "ordinary encrypted Invite produced an invitation without dedicated admission"
    );

    let denied = context.denied_holder.account.clone();
    let request = prepare_invitation(context, &call, &denied, media.clone(), *sequence).await?;
    *sequence += 1;
    ensure!(
        product_attempt(
            context,
            &context.denied_holder,
            denied_native,
            &request,
            true
        )
        .await?
            == 0
    );
    let mut denied_token = invited_token(context, &request, media);
    denied_token.actor_id = context.denied_holder.actor.clone();
    denied_token.device_id = context.denied_holder.device.clone();
    reject_token(&context, &context.denied_holder, &denied_token).await?;
    let mut borrowed = token;
    borrowed.actor_id = context.denied_holder.actor.clone();
    borrowed.device_id = context.denied_holder.device.clone();
    reject_token(&context, &context.denied_holder, &borrowed).await?;
    revoke(&context.holder, &permission).await?;
    Ok(())
}

async fn relation_mutations(
    context: &mut ConsentCallContext,
    native: &inkson::sync_engine::NativeAccountHost,
    sequence: &mut u64,
) -> Result<()> {
    let (permission, _) = grant(
        context,
        &context.holder,
        ConsentScope::VoiceCall,
        None,
        None,
        None,
    )
    .await?;
    let call = new_call(context).await?;
    let holder = context.holder.account.clone();
    let request = prepare_invitation(
        context,
        &call,
        &holder,
        CallInvitationMedia {
            audio: true,
            video: false,
            screen: false,
        },
        *sequence,
    )
    .await?;
    *sequence += 1;
    let token = invited_token(context, &request, request.invitation.media.clone());
    verify_token(context, &token, &exchange(&context.holder, &token).await?).await?;
    for axis in 0..10 {
        let mut changed = token.clone();
        let CallMediaJoinContext::Invitation(invited) = &mut changed.join_context else {
            unreachable!()
        };
        match axis {
            0 => invited.invitation.holder_account_id = context.denied_holder.account.clone(),
            1 => {
                let account = context
                    .caller
                    .actor
                    .as_account_id()
                    .context("full inviter")?;
                invited.invitation.inviter_actor_id =
                    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        account.principal_id.clone(),
                        context.stations.server(2).service_id().clone(),
                    ));
            }
            2 => invited.invitation.call_id = CallId::from_event_id(&context.accepted_group),
            3 => {
                invited.invitation.scope_ref = ScopeRef::Realm {
                    realm_id: arkret_wire::RealmId::from_event_id(&context.accepted_group),
                }
            }
            4 => invited.invitation.media.audio = false,
            5 => {
                invited.invitation.proof.verification_method =
                    context.denied_holder.method.to_string()
            }
            6 => {
                invited.invitation.envelope_digest =
                    arkret_canonical::sha256_digest(b"different ciphertext")
            }
            7 => changed.device_id = context.denied_holder.device.clone(),
            8 => {
                invited.envelope.proof.audience = Some(arkret_wire::Audience::Single(
                    context.stations.server(2).service_id().to_string(),
                ));
                invited.envelope.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
                    &context.caller.key,
                    &invited.envelope.proof_binding_bytes()?,
                )?;
                invited.invitation.envelope_digest = canonical_request_digest(&invited.envelope)?;
            }
            9 => {
                let mut bytes = arkret_canonical::base64url_decode(
                    &invited.envelope.encrypted_payload.ciphertext,
                )?;
                bytes[0] ^= 1;
                invited.envelope.encrypted_payload.ciphertext =
                    arkret_canonical::base64url_encode(bytes);
            }
            _ => unreachable!(),
        }
        if let CallMediaJoinContext::Invitation(invited) = &mut changed.join_context {
            invited.invitation.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
                &context.caller.key,
                &invited.invitation.signature_input()?,
            )?;
        }
        reject_token(&context, &context.holder, &changed).await?;
    }
    for mutation in 0..3 {
        let other_call = new_call(context).await?;
        let changed = prepare_invitation_with_plaintext(
            context,
            &other_call,
            &holder,
            request.invitation.media.clone(),
            *sequence,
            Some(mutation),
        )
        .await?;
        *sequence += 1;
        ensure!(
            product_attempt(context, &context.holder, native, &changed, true).await? == 0,
            "exact signed encrypted relation released wrong actual plaintext {mutation}"
        );
    }
    revoke(&context.holder, &permission).await?;
    Ok(())
}

async fn independent_windows(
    context: &mut ConsentCallContext,
    native: &inkson::sync_engine::NativeAccountHost,
    sequence: &mut u64,
) -> Result<()> {
    let mut invalid = Vec::new();
    let now = Utc::now();
    invalid.push(
        grant(
            context,
            &context.holder,
            ConsentScope::VoiceCall,
            None,
            Some(now + Duration::seconds(5)),
            None,
        )
        .await?
        .0,
    );
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    for (begin, end, constraints) in [
        (Some(now + Duration::minutes(5)), None, None),
        (
            None,
            None,
            Some(vec![std::collections::BTreeMap::from([(
                "unknown_constraint".to_owned(),
                serde_json::json!(true),
            )])]),
        ),
    ] {
        invalid.push(
            grant(
                context,
                &context.holder,
                ConsentScope::VoiceCall,
                begin,
                end,
                constraints,
            )
            .await?
            .0,
        );
    }
    let current = inkson::conformance::read_native_consent_current(
        native,
        context.caller.actor.clone(),
        ConsentScope::VoiceCall,
    )
    .await?;
    ensure!(!inkson::conformance::consume_native_consent_current(native, &current).await?);
    let call = new_call(context).await?;
    let holder = context.holder.account.clone();
    let request = prepare_invitation(
        context,
        &call,
        &holder,
        CallInvitationMedia {
            audio: true,
            video: false,
            screen: false,
        },
        *sequence,
    )
    .await?;
    *sequence += 1;
    let token = invited_token(context, &request, request.invitation.media.clone());
    reject_token(&context, &context.holder, &token).await?;
    let (concrete, _) = grant(
        context,
        &context.holder,
        ConsentScope::VoiceCall,
        None,
        None,
        None,
    )
    .await?;
    let (any, _) = grant(
        context,
        &context.holder,
        ConsentScope::Any,
        None,
        None,
        None,
    )
    .await?;
    revoke(&context.holder, &any).await?;
    let current = inkson::conformance::read_native_consent_current(
        native,
        context.caller.actor.clone(),
        ConsentScope::VoiceCall,
    )
    .await?;
    ensure!(inkson::conformance::consume_native_consent_current(native, &current).await?);
    ensure!(
        current
            .value()?
            .consents
            .iter()
            .any(|row| row.value.consent_id == concrete.consent_id
                && row.revision == concrete.revision)
    );
    verify_token(context, &token, &exchange(&context.holder, &token).await?).await?;
    let (other_any, _) = grant(
        context,
        &context.holder,
        ConsentScope::Any,
        None,
        None,
        None,
    )
    .await?;
    revoke(&context.holder, &concrete).await?;
    let current = inkson::conformance::read_native_consent_current(
        native,
        context.caller.actor.clone(),
        ConsentScope::VoiceCall,
    )
    .await?;
    ensure!(inkson::conformance::consume_native_consent_current(native, &current).await?);
    verify_token(context, &token, &exchange(&context.holder, &token).await?).await?;
    revoke(&context.holder, &other_any).await?;
    reject_token(&context, &context.holder, &token).await?;
    for permission in invalid {
        revoke(&context.holder, &permission).await?;
    }
    Ok(())
}

async fn presence_peer_grant(
    context: &ConsentCallContext,
    peer: &arkret_wire::ActorId,
    scope: ConsentScope,
) -> Result<ConsentView> {
    let holder = &context.holder;
    let realm = &holder
        .client
        .principal
        .as_ref()
        .context("holder PCR")?
        .pcr_realm_id;
    let event=holder.client.author_event(realm.as_str(),EventKind::ConsentGrant.as_str(),serde_json::json!({"consent_id":next_typed_id("consent"),"peer":{"kind":"actor","actor_id":peer},"consent_scope":scope})).await?;
    Ok(serde_json::from_value(
        expect_json(
            holder
                .client
                .post("/_arkret/self/consent/results/grant")
                .json(&ConsentGrantRequestBody {
                    grant_event: EventAdmissionSubmission::new(event),
                }),
            StatusCode::OK,
        )
        .await?,
    )?)
}
async fn presence_attempt(
    context: &ConsentCallContext,
    native: &inkson::sync_engine::NativeAccountHost,
    receiver_native: &inkson::sync_engine::NativeAccountHost,
    allowed: bool,
) -> Result<()> {
    eprintln!("[2141-live] Presence actual send attempt allowed={allowed}");
    let mut stream = ready_stream(&context.caller).await?;
    let _signer =
        super::account_blocklist_projection::ActiveEndpointSigner::install(&context.holder)?;
    let material = inkson::signal::key_material_for_scope(
        &native.state_store(),
        context.realm.as_str(),
        None,
    )?;
    let payload = inkson::signal::SignalPayload::Presence {
        state: "online".into(),
        status_message: None,
        last_active_at: None,
    };
    let sent = native
        .send_scope_signal(
            ScopeRef::Realm {
                realm_id: context.realm.clone(),
            },
            &material,
            &payload,
        )
        .await;
    eprintln!(
        "[2141-live] Presence actual sender allowed={allowed} submitted={}",
        sent.is_ok()
    );
    if !allowed {
        ensure!(
            sent.is_err(),
            "Presence emitted an encrypted whole-scope Signal without authorization"
        );
        return Ok(());
    }
    ensure!(
        sent?.accepted,
        "authorized actual Presence Signal was not accepted"
    );
    let received = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        super::account_blocklist_projection::next_admitted_signal(
            &mut stream,
            receiver_native,
            &context.caller,
            &mut garth::signal::SignalReceiver::new(),
        ),
    )
    .await
    .context("actual Presence delivery timed out")??;
    let garth::signal::SignalReceiveOutcome::Accepted {
        domain, plaintext, ..
    } = received
    else {
        anyhow::bail!("actual Presence did not pass device/MLS receipt admission")
    };
    ensure!(
        domain.sender_actor_id == context.holder.actor
            && matches!(*plaintext, arkret::SignalPlaintext::Presence(_)),
        "actual Presence sender/plaintext mismatch"
    );
    Ok(())
}
async fn presence_current(
    context: &ConsentCallContext,
    native: &inkson::sync_engine::NativeAccountHost,
    directory: &tempfile::TempDir,
) -> Result<()> {
    use arkret::PresenceVisibility;
    let receiver = super::account_blocklist_projection::native_signal_endpoint(
        &context.caller,
        &context.realm,
        &context.accepted_group,
        &context.caller_group,
        &directory.path().join("presence-receiver.json"),
    )
    .await?;
    let store = native.state_store_handle();
    store.write(|s| s.set_presence_visibility(PresenceVisibility::ConsentOnly));
    cotest::harness::heap_future(|| presence_attempt(context, native, &receiver, false)).await?;
    let caller =
        presence_peer_grant(context, &context.caller.actor, ConsentScope::Presence).await?;
    cotest::harness::heap_future(|| presence_attempt(context, native, &receiver, false)).await?;
    let other =
        presence_peer_grant(context, &context.denied_holder.actor, ConsentScope::Any).await?;
    cotest::harness::heap_future(|| presence_attempt(context, native, &receiver, true)).await?;
    revoke(&context.holder, &other).await?;
    cotest::harness::heap_future(|| presence_attempt(context, native, &receiver, false)).await?;
    presence_peer_grant(
        context,
        &context.denied_holder.actor,
        ConsentScope::Presence,
    )
    .await?;
    let independent =
        presence_peer_grant(context, &context.caller.actor, ConsentScope::Any).await?;
    revoke(&context.holder, &caller).await?;
    cotest::harness::heap_future(|| presence_attempt(context, native, &receiver, true)).await?;
    revoke(&context.holder, &independent).await?;
    cotest::harness::heap_future(|| presence_attempt(context, native, &receiver, false)).await?;
    store.write(|s| s.set_presence_visibility(PresenceVisibility::Nobody));
    cotest::harness::heap_future(|| presence_attempt(context, native, &receiver, false)).await?;
    store.write(|s| s.set_presence_visibility(PresenceVisibility::ContactsOnly));
    cotest::harness::heap_future(|| presence_attempt(context, native, &receiver, false)).await?;
    store.write(|s| s.set_presence_visibility(PresenceVisibility::Public));
    cotest::harness::heap_future(|| presence_attempt(context, native, &receiver, true)).await?;
    println!(
        "[2141-live] actual_presence_whole_scope=1 partial_audience_denied=1 any_independent=1 revoke_before_send=1 nobody_denied=1 contacts_no_consent_fallback=1 explicit_public=1 actual_device_mls_decrypt=1"
    );
    Ok(())
}

async fn actual_product(
    context: &mut ConsentCallContext,
    native: &inkson::sync_engine::NativeAccountHost,
    sequence: &mut u64,
) -> Result<(
    CallInvitationSendRequestBody,
    garth::signal::SignalReceiveOutcome,
)> {
    let call = new_call(context).await?;
    let holder = context.holder.account.clone();
    let invitation = prepare_invitation(
        context,
        &call,
        &holder,
        CallInvitationMedia {
            audio: true,
            video: false,
            screen: false,
        },
        *sequence,
    )
    .await?;
    *sequence += 1;
    native
        .catch_up_selected_realm_until_complete(&context.realm)
        .await?;
    let mut stream = ready_stream(&context.holder).await?;
    send(context, &invitation).await?;
    let received = super::account_blocklist_projection::next_admitted_signal(
        &mut stream,
        native,
        &context.holder,
        &mut garth::signal::SignalReceiver::new(),
    )
    .await?;
    ensure!(
        matches!(
            &received,
            garth::signal::SignalReceiveOutcome::Accepted {
                call_invitation: Some(_),
                ..
            }
        ),
        "actual product outcome is missing"
    );
    Ok((invitation, received))
}
fn arm_emission(
    path: &std::path::Path,
    request: &CallInvitationSendRequestBody,
) -> Result<std::path::PathBuf> {
    let selected = vec![(
        request.invitation.holder_account_id.clone(),
        request.envelope.proof.envelope_digest.clone(),
    )];
    let pause = path.with_extension("0.pause");
    for suffix in ["reached.json", "outcome.json", "skip"] {
        let _ = std::fs::remove_file(pause.with_extension(suffix));
    }
    std::fs::write(&pause, [])?;
    std::fs::write(path, arkret_canonical::canonical_json_bytes(&selected)?)?;
    Ok(pause)
}
async fn wait_emission(path: &std::path::Path, extension: &str) -> Result<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match std::fs::read(path.with_extension(extension)) {
            Ok(bytes) => {
                if let Ok(value) = serde_json::from_slice(&bytes) {
                    return Ok(value);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "physical Consent emission boundary was not observed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
async fn call_projection_failure(
    context: &ConsentCallContext,
    native: &inkson::sync_engine::NativeAccountHost,
    request: &CallInvitationSendRequestBody,
    admitted: String,
    phase: String,
) -> anyhow::Error {
    let current = inkson::conformance::retained_realm_current(
        &native.state_store(),
        &context.holder.account,
        &context.realm,
    )
    .await;
    let fresh_consent = inkson::conformance::read_native_call_consent(native, &request.invitation)
        .await
        .and_then(|read| read.permits(None, &[], Utc::now()).map_err(Into::into));
    anyhow::anyhow!(
        "{phase}: admitted={admitted}, current={current:?}, fresh_consent={fresh_consent:?}"
    )
}

async fn queued_revoke(
    context: &mut ConsentCallContext,
    native: &inkson::sync_engine::NativeAccountHost,
    path: &std::path::Path,
    sequence: &mut u64,
) -> Result<()> {
    for websocket in [false, true] {
        let (permission, _) = grant(
            context,
            &context.holder,
            ConsentScope::VoiceCall,
            None,
            None,
            None,
        )
        .await?;
        for allowed in [true, false] {
            let call = new_call(context).await?;
            let holder = context.holder.account.clone();
            let request = prepare_invitation(
                context,
                &call,
                &holder,
                CallInvitationMedia {
                    audio: true,
                    video: false,
                    screen: false,
                },
                *sequence,
            )
            .await?;
            *sequence += 1;
            native
                .catch_up_selected_realm_until_complete(&context.realm)
                .await?;
            let mut stream = if websocket {
                let mut stream = cotest::scenarios::websocket_live::LiveSignalReader::connect(
                    context.stations.server(1),
                    &context.holder.client,
                    context.realm.as_str(),
                )
                .await?;
                ensure!(
                    matches!(
                        stream.next_frame().await?,
                        Some(arkret_models_collaboration::SignalStreamFrame::Heartbeat)
                    ),
                    "WebSocket Signal subscription not ready"
                );
                PhysicalSignalRail::WebSocket(Box::new(stream))
            } else {
                PhysicalSignalRail::Http(ready_stream(&context.holder).await?)
            };
            let pause = arm_emission(path, &request)?;
            if websocket {
                std::fs::write(pause.with_extension("skip"), [])?;
            }
            send(context, &request).await?;
            let reached = wait_emission(&pause, "reached.json").await?;
            ensure!(
                reached == serde_json::to_value(&request.envelope)?,
                "pause did not hold the exact queued ciphertext"
            );
            if !allowed {
                revoke(&context.holder, &permission).await?;
            }
            ensure!(
                request.invitation.expires_at > Utc::now(),
                "queued revoke test crossed the invitation window"
            );
            std::fs::remove_file(&pause)?;
            let outcome = wait_emission(&pause, "outcome.json").await?;
            ensure!(
                outcome["admitted"] == true
                    && outcome["call_invitation"] == serde_json::json!(allowed),
                "actual physical gate did not re-evaluate product Consent"
            );
            if allowed {
                let received = stream.admit(native, &context.holder).await?;
                let admitted = format!("{received:?}");
                let rings =
                    inkson::conformance::observe_native_call_projection(native, received).await?;
                if rings != 1 {
                    return Err(cotest::harness::heap_future(|| {
                        call_projection_failure(
                            context,
                            native,
                            &request,
                            admitted,
                            format!("paused positive control did not ring: websocket={websocket}"),
                        )
                    })
                    .await);
                }
            } else {
                let received = stream.admit(native, &context.holder).await?;
                ensure!(
                    matches!(
                        &received,
                        garth::signal::SignalReceiveOutcome::Accepted {
                            call_invitation: None,
                            ..
                        }
                    ),
                    "revoked queued output retained a product verdict"
                );
                ensure!(
                    inkson::conformance::observe_native_call_projection(native, received).await?
                        == 0,
                    "ordinary encrypted output rang after queued product revocation"
                );
                reject_token(
                    context,
                    &context.holder,
                    &invited_token(context, &request, request.invitation.media.clone()),
                )
                .await?;
            }
        }
    }
    let (permission, _) = grant(
        context,
        &context.holder,
        ConsentScope::VoiceCall,
        None,
        None,
        None,
    )
    .await?;
    let (request, received) = actual_product(context, native, sequence).await?;
    revoke(&context.holder, &permission).await?;
    ensure!(
        inkson::conformance::observe_native_call_projection(native, received).await? == 0,
        "in-flight pre-revoke product rang after the revoke"
    );
    reject_token(
        context,
        &context.holder,
        &invited_token(context, &request, request.invitation.media.clone()),
    )
    .await?;
    println!(
        "[2141-live] actual_http_and_websocket_paused_positive=2 revoke_before_physical_product=2 inflight_revoke_before_ring=1 revoke_before_token=1"
    );
    Ok(())
}
async fn reopen_native(
    context: &ConsentCallContext,
    previous: &inkson::sync_engine::NativeAccountHost,
) -> Result<inkson::sync_engine::NativeAccountHost> {
    // Cold RTC opened this same durable root; resume with its committed metadata.
    Ok(inkson::sync_engine::NativeAccountHost::new_for_realm(
        context.holder.client.sdk(),
        context.holder.account.clone(),
        context.holder.device.clone(),
        previous.state_store().conformance_reopen(),
        context.realm.clone(),
    )
    .await?)
}

/// Keep the original thirty-second verdict live across the actual authority cut.
pub async fn run_authority_change_live() -> Result<()> {
    let mut context = cotest::harness::heap_future(|| async {
        ConsentCallContext::create("consent-authority-live", &[])
            .await
            .map(Box::new)
    })
    .await?;
    install_media(
        &context,
        "arkret_native",
        "https://media.consent.invalid/connect",
    )
    .await?;
    let directory = tempfile::tempdir()?;
    let native = cotest::harness::heap_future(|| async {
        super::account_blocklist_projection::native_signal_endpoint(
            &context.holder,
            &context.realm,
            &context.accepted_group,
            &context.holder_group,
            &directory.path().join("holder.json"),
        )
        .await
        .map(Box::new)
    })
    .await?;
    let fresh = reopen_native(&context, &native).await?;
    let mut sequence = 1;
    cotest::harness::heap_future(|| authority_change(&mut context, &fresh, &mut sequence)).await
}

async fn authority_change(
    context: &mut ConsentCallContext,
    native: &inkson::sync_engine::NativeAccountHost,
    sequence: &mut u64,
) -> Result<()> {
    grant(
        context,
        &context.holder,
        ConsentScope::VoiceCall,
        None,
        None,
        None,
    )
    .await?;
    for (from, to) in [(1, 2), (2, 0)] {
        let (request, received) = actual_product(context, native, sequence)
            .await
            .context("authority-change original actual product")?;
        let started = std::time::Instant::now();
        let old = inkson::conformance::read_native_consent_current(
            native,
            context.caller.actor.clone(),
            ConsentScope::VoiceCall,
        )
        .await?;
        let previous = old.value()?.governance_generation;
        let recovery = cotest::harness::heap_future(|| {
            cotest::scenarios::consent_pcr_handoff::activate_handoff(context, from, to)
        })
        .await
        .context("authority-change native PCR handoff")?;
        let fresh = inkson::conformance::read_native_consent_current(
            native,
            context.caller.actor.clone(),
            ConsentScope::VoiceCall,
        )
        .await?;
        ensure!(
            fresh.value()?.governance_generation == previous + 1,
            "actual PCR tenure did not advance once"
        );
        ensure!(
            inkson::conformance::consume_native_consent_current(native, &fresh).await?,
            "new authority's real holder read did not recover"
        );
        ensure!(
            inkson::conformance::consume_native_consent_current(native, &old)
                .await
                .is_err(),
            "older authority read crossed the known tenure high water"
        );
        eprintln!(
            "[2141-authority] from_generation={previous} activation_and_current_ms={} original_invitation_remaining_ms={}",
            started.elapsed().as_millis(),
            (request.invitation.expires_at - Utc::now()).num_milliseconds()
        );
        ensure!(
            request.invitation.expires_at > Utc::now(),
            "authority switch test lost its original unexpired invitation"
        );
        if let garth::signal::SignalReceiveOutcome::Accepted {
            call_invitation: Some(view),
            ..
        } = &received
        {
            ensure!(
                view.outcome.expires_at > Utc::now(),
                "authority switch lost its original unexpired product verdict"
            );
        }
        ensure!(
            inkson::conformance::observe_native_call_projection(native, received).await? == 0,
            "previous-authority product rang after authority switch"
        );
        cotest::harness::heap_future(|| {
            cotest::scenarios::consent_pcr_handoff::recover_handoff(context, recovery)
        })
        .await?;
        // The original ciphertext was already decrypted before handoff. Recovery
        // must author a fresh Signal rather than bypass the MLS replay guard.
        let retry = prepare_invitation(
            context,
            &request.invitation.call_id,
            &request.invitation.holder_account_id,
            request.invitation.media.clone(),
            *sequence,
        )
        .await?;
        *sequence += 1;
        ensure!(
            product_attempt_after_current(context, &context.holder, native, &retry, true).await?
                == 1,
            "fresh authority retry did not pass the real product/ring cuts"
        );
        let token = invited_token(context, &retry, retry.invitation.media.clone());
        let outcome = exchange(&context.holder, &token).await?;
        verify_token(context, &token, &outcome).await?;
    }
    println!(
        "[2141-live] actual_zero_nonzero_pcr_handoff=1 previous_authority_read_rejected=1 previous_product_rejected=1 fresh_product_ring_token_recovered=1"
    );
    Ok(())
}

async fn opaque_response(context: &mut ConsentCallContext, sequence: &mut u64) -> Result<()> {
    let call = new_call(context).await?;
    let media = CallInvitationMedia {
        audio: true,
        video: false,
        screen: false,
    };
    let revoked = context.holder.account.clone();
    let never = context.denied_holder.account.clone();
    let absent = arkret_wire::AccountId::new(
        "ak:did_core:web:absent.consent.example".parse()?,
        context.holder.account.station_id.clone(),
    );
    for holder in [&revoked, &never, &absent] {
        let request = prepare_invitation(context, &call, holder, media.clone(), *sequence).await?;
        *sequence += 1;
        send(context, &request).await?;
    }
    let mut samples = [Vec::new(), Vec::new()];
    for sample in 0..24 {
        for index in [sample % 2, 1 - sample % 2] {
            // Each timing sample is a fresh encrypted submission, outside the
            // measured HTTP interval and within its original signed window.
            let holder = if index == 0 { &revoked } else { &never };
            let request =
                prepare_invitation(context, &call, holder, media.clone(), *sequence).await?;
            *sequence += 1;
            let start = std::time::Instant::now();
            send(context, &request).await?;
            samples[index].push(start.elapsed().as_secs_f64());
        }
    }
    for values in &mut samples {
        values.sort_by(f64::total_cmp);
    }
    let mut distance = 0.0_f64;
    for value in samples.iter().flatten() {
        let left = samples[0].partition_point(|sample| sample <= value) as f64 / 24.0;
        let right = samples[1].partition_point(|sample| sample <= value) as f64 / 24.0;
        distance = distance.max((left - right).abs());
    }
    // Two-sample KS, alpha 0.01. Identical async acknowledgements do not wait
    // for the private receiver's allow/revoke decision; test both orderings.
    let threshold = 1.63 * (2.0_f64 / 24.0).sqrt();
    ensure!(
        distance < threshold,
        "revoked versus never-matching sender timing separated: KS={distance} limit={threshold}"
    );
    println!(
        "[2141-live] actual_opaque_sender_shapes=3 interleaved_timing_samples_per_class=24 ks_distance={distance:.3} alpha=0.01"
    );
    Ok(())
}

async fn private_refresh_matrix(
    context: &mut ConsentCallContext,
    token: &CallMediaTokenExchangeRequestBody,
    accepted: &CallMediaTokenExchangeOutcome,
    unaccepted: &CallMediaTokenExchangeOutcome,
) -> Result<()> {
    use ed25519_dalek::Signer as _;
    reject_token(context, &context.holder, &refresh(token, unaccepted)).await?;
    let signer = context.stations.server(1).federation_signing_key()?;
    for mutation in 0..8 {
        let mut request = refresh(token, accepted);
        let CallMediaJoinContext::Refresh(join) = &mut request.join_context else {
            unreachable!()
        };
        match mutation {
            0 => join.subject_binding.subject_actor_id = context.denied_holder.actor.clone(),
            1 => join.subject_binding.subject_device_id = context.denied_holder.device.clone(),
            2 => {
                join.subject_binding.roster_identity.actor_id =
                    context.caller.account.principal_id.clone()
            }
            3 => join.subject_binding.roster_identity.device_id = context.holder.device.clone(),
            4 => {
                join.subject_binding.expires_at = arkret_canonical::normalize_timestamp_canonical(
                    Utc::now() - Duration::seconds(1),
                )
            }
            5 => join.subject_binding.media.video = !join.subject_binding.media.video,
            6 => join.subject_binding.nonce = arkret_canonical::base64url_encode([0xb5; 32]),
            7 => join.subject_binding.participant_id.push('x'),
            _ => unreachable!(),
        }
        join.subject_binding.sig = arkret_canonical::base64url_encode(
            signer
                .sign(&join.subject_binding.signature_input()?)
                .to_bytes(),
        );
        reject_token(context, &context.holder, &request).await?;
    }
    let mut bad_signature = refresh(token, accepted);
    let CallMediaJoinContext::Refresh(join) = &mut bad_signature.join_context else {
        unreachable!()
    };
    join.subject_binding.sig = arkret_canonical::base64url_encode([0x44; 64]);
    reject_token(context, &context.holder, &bad_signature).await?;
    let mut other_station = refresh(token, accepted);
    let CallMediaJoinContext::Refresh(join) = &mut other_station.join_context else {
        unreachable!()
    };
    join.subject_binding.issuer_kid = arkret_wire::DidUrl::new(format!(
        "{}#notary-key",
        context.stations.server(0).service_did()
    ))
    .map_err(anyhow::Error::msg)?;
    join.subject_binding.sig = arkret_canonical::base64url_encode(
        context
            .stations
            .server(0)
            .federation_signing_key()?
            .sign(&join.subject_binding.signature_input()?)
            .to_bytes(),
    );
    reject_token(context, &context.holder, &other_station).await?;
    reject_token(context, &context.denied_holder, &refresh(token, accepted)).await?;
    context
        .stations
        .server_mut(1)
        .restart_external_process()
        .await?;
    let request = refresh(token, accepted);
    verify_token(
        context,
        &request,
        &exchange(&context.holder, &request).await?,
    )
    .await?;
    let seed = arkret_canonical::base64_standard_encode([0xa7; 32]);
    context
        .stations
        .server_mut(1)
        .restart_external_process_with_notary_signing_key(&seed)
        .await?;
    let rotated = exchange(&context.holder, &request).await?;
    verify_token(context, &request, &rotated).await?;
    ensure!(
        rotated.subject_binding.sig != accepted.subject_binding.sig,
        "rotation did not produce a fresh private receipt"
    );
    reject_token(context, &context.holder, &refresh(token, unaccepted)).await?;
    accept_roster(context, &context.holder, &rotated).await?;
    let current = refresh(token, &rotated);
    verify_token(
        context,
        &current,
        &exchange(&context.holder, &current).await?,
    )
    .await?;
    reject_token(context, &context.holder, &request).await?;
    println!(
        "[2141-live] receipt_signed_mismatch_denials=8 bad_signature_denied=1 wrong_station_denied=1 wrong_subject_denied=1 valid_unaccepted_denied=1 durable_restart_refresh=1 historical_issuer_rotation_refresh=1 superseded_public_commitment_denied=1"
    );
    Ok(())
}

const FIXTURE: &str = "consent-cache-invalidation-fixture.json";
const CASE_NAMES: [&str; 14] = [
    "excluded_private_discovery_and_psi_remain_unavailable",
    "cached_invite_gate_is_reevaluated_before_the_next_submission",
    "an_any_scope_revoke_clears_every_scope_cache",
    "older_reads_and_exact_retries_never_rollback_current_revision",
    "revocation_is_not_distinguishable_from_never_matching",
    "call_invitation_three_cuts_allow_a_legal_voice_and_video_call",
    "call_invitation_plain_rail_cannot_enter_product",
    "call_invitation_exact_relation_and_plaintext_mismatch",
    "call_invitation_each_holder_is_independent",
    "call_invitation_window_constraints_and_independent_grants",
    "call_invitation_cross_station_inflight_revoke_and_queue",
    "call_invitation_older_read_retry_and_authority_change",
    "call_invitation_first_join_voluntary_refresh_and_expansion",
    "call_invitation_opaque_response_and_recovery",
];
fn completed_case(
    results: &mut Vec<super::CaseExecutionResult>,
    index: usize,
    assertions: usize,
) -> Result<()> {
    ensure!(
        !results.iter().any(|r| r.case_id == CASE_NAMES[index]),
        "Consent case executed twice"
    );
    results.push(super::CaseExecutionResult {
        case_id: CASE_NAMES[index].to_owned(),
        assertions,
    });
    println!("[2141-case] {} assertions={assertions}", CASE_NAMES[index]);
    Ok(())
}

pub async fn run_consent_cache_suite_live() -> Result<super::SuiteExecutionResult> {
    let fixture = super::load_fixture_value(FIXTURE)?;
    ensure!(
        super::fixture_runner_entrypoint(&fixture)? == CONSENT_CACHE_ENTRYPOINT,
        "Consent named entrypoint drift"
    );
    let declared = super::value_array(super::required_field(&fixture, "cases")?, "cases")?;
    ensure!(
        declared.len() == CASE_NAMES.len(),
        "Consent required case count changed"
    );
    for (case, name) in declared.iter().zip(CASE_NAMES) {
        ensure!(case["name"] == name, "Consent case contract changed");
    }
    // These original production flows are required predecessors of cases 1, 2 and 11.
    cotest::harness::heap_future(cotest::scenarios::consent_pcr_handoff::run_planned_handoff_live)
        .await?;
    cotest::harness::heap_future(
        cotest::scenarios::invite_service_fanout_live::consent_current_and_invite_gate_live_run,
    )
    .await?;
    let mut cases = cotest::harness::heap_future(run_three_cuts_evidence).await?;
    completed_case(&mut cases, 1, 6)?;
    completed_case(&mut cases, 11, 12)?;
    cases.sort_by_key(|case| {
        CASE_NAMES
            .iter()
            .position(|name| *name == case.case_id)
            .expect("recorded case")
    });
    let result = super::SuiteExecutionResult {
        entrypoint: CONSENT_CACHE_ENTRYPOINT,
        fixture: FIXTURE,
        cases,
    };
    result.assert_complete_against(&fixture)?;
    Ok(result)
}

pub fn run_consent_cache_suite() -> Result<super::SuiteExecutionResult> {
    std::thread::spawn(|| -> Result<_> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        runtime.block_on(
            tokio::task::LocalSet::new()
                .run_until(cotest::harness::heap_future(run_consent_cache_suite_live)),
        )
    })
    .join()
    .map_err(|_| anyhow::anyhow!("Consent named production runner panicked"))?
}

async fn consent_commit_count(context: &ConsentCallContext) -> Result<i64> {
    let url = context.databases[1].connect_url.clone();
    let realm = context
        .holder
        .client
        .principal
        .as_ref()
        .context("exact holder PCR")?
        .pcr_realm_id
        .to_string();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        Ok(db
            .query_one(
                "SELECT count(*) FROM realm_commits WHERE realm_id=$1",
                &[&realm],
            )?
            .get(0))
    })
    .await?
}

enum PhysicalSignalRail {
    Http(arkret_http_client::SignalSubscribeFrameStream),
    WebSocket(Box<cotest::scenarios::websocket_live::LiveSignalReader>),
}
impl PhysicalSignalRail {
    async fn admit(
        &mut self,
        host: &inkson::sync_engine::NativeAccountHost,
        member: &Member,
    ) -> Result<garth::signal::SignalReceiveOutcome> {
        let decryptor = inkson::signal_receive_engine::MlsSignalDecryptor::new(
            host.state_store_handle(),
            member.account.clone(),
            member.device.clone(),
        );
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let frame = match self {
                    Self::Http(stream) => stream.next_frame().await?,
                    Self::WebSocket(stream) => stream.next_frame().await?,
                };
                match frame.context("physical Signal rail ended")? {
                    arkret_models_collaboration::SignalStreamFrame::Signal {
                        envelope,
                        delivery_authority,
                    } => {
                        return Ok::<_, anyhow::Error>(
                            garth::signal::SignalReceiver::new()
                                .receive(&envelope, &delivery_authority, &decryptor, Utc::now())
                                .await?,
                        );
                    }
                    arkret_models_collaboration::SignalStreamFrame::Heartbeat => {}
                    _ => anyhow::bail!("physical Signal rail closed before delivery"),
                }
            }
        })
        .await
        .context("physical product output timed out")?
    }
}
