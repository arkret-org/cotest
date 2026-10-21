//! Real producer, holder Station, native ringing and media-token admission.

mod material_recovery;
mod media_verification;
mod token_release;

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::call_invitation::*;
use arkret_models_collaboration::consent_operations::{ConsentReplaceRequestBody, ConsentView};
use arkret_models_collaboration::events_payloads::RealmMediaServicePayload;
use arkret_models_collaboration::events_payloads::call::{CallCreatePayload, CallLifecycleState};
use arkret_models_collaboration::events_payloads::consent::ConsentPermission;
use arkret_wire::{ActorId, ConsentScope, EventAdmissionSubmission, EventKind, ScopeRef};
use cotest::scenarios::mls_lifecycle_live::{Member, MlsClientObserver, fresh_uuid_v7};

use super::account_blocklist_projection::{
    ActiveEndpointSigner, native_call_endpoint, next_admitted_signal,
};
use super::consent_support::PermissionGrant;

pub async fn run_legal_three_cut_calls() -> Result<()> {
    let observer = CallAdmissionObserver::default();
    Box::pin(
        cotest::scenarios::mls_lifecycle_live::run_with_blocklist_observer(Some(&observer), false),
    )
    .await
}

pub async fn run_cross_station_three_cut_calls() -> Result<()> {
    let observer = CallAdmissionObserver::default();
    Box::pin(cotest::scenarios::message_mls_cross_station_live::run_with_call_observer(&observer))
        .await
}

#[derive(Default)]
struct CallAdmissionObserver {
    refreshes: std::sync::Mutex<
        Vec<(
            arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
            chrono::DateTime<chrono::Utc>,
        )>,
    >,
    recoveries: std::sync::atomic::AtomicUsize,
    emission_probe: std::sync::Mutex<Option<std::path::PathBuf>>,
}
impl CallAdmissionObserver {
    async fn observe_ordinary_call_invite(
        &self,
        sender: &Member,
        holder: &Member,
        station: &cotest::harness::ArkretServer,
        holder_station: &cotest::harness::ArkretServer,
        realm: &arkret_wire::RealmId,
        accepted_group: &arkret_wire::EventId,
        sender_group: &mut arkret::ArkretMlsGroup,
        holder_group: &arkret::ArkretMlsGroup,
        observe_receipt: bool,
        other_holder: Option<(&Member, &arkret::ArkretMlsGroup)>,
    ) -> Result<()> {
        ensure!(
            !observe_receipt,
            "Consent call runner cannot enter receipt mode"
        );
        eprintln!("[consent-call] phase=accepted_mls");
        // Keep the actual fixture leases alive while the call slice runs on
        // an independent default-stack executor, outside provisioning's poll.
        let emission_probe = self
            .emission_probe
            .lock()
            .map_err(|_| anyhow::anyhow!("emission probe lock poisoned"))?
            .clone();
        let refreshes = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()?
                        .block_on(Box::pin(run_at_accepted_mls(
                            sender,
                            holder,
                            station,
                            holder_station,
                            realm,
                            accepted_group,
                            sender_group,
                            holder_group,
                            emission_probe.as_deref(),
                            other_holder,
                        )))
                })
                .join()
                .map_err(|_| anyhow::anyhow!("accepted Call worker panicked"))?
        })?;
        self.refreshes
            .lock()
            .map_err(|_| anyhow::anyhow!("Call recovery evidence lock poisoned"))?
            .extend(refreshes);
        Ok(())
    }

    async fn after_station_restart(&self, holder: &Member) -> Result<()> {
        let after_rotation = self
            .recoveries
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            != 0;
        let refreshes = self
            .refreshes
            .lock()
            .map_err(|_| anyhow::anyhow!("Call recovery evidence lock poisoned"))?
            .clone();
        ensure!(
            refreshes.len() == 2,
            "both accepted media legs must reach restart recovery"
        );
        for (request, accepted_expiry) in refreshes {
            if accepted_expiry >= chrono::Utc::now() {
                let delay = (accepted_expiry - chrono::Utc::now()).to_std()?;
                ensure!(
                    delay <= std::time::Duration::from_secs(35),
                    "live expiry evidence requires the configured short binding TTL"
                );
                tokio::time::sleep(delay + std::time::Duration::from_millis(10)).await;
            }
            ensure!(
                chrono::Utc::now() > accepted_expiry,
                "original accepted binding must actually be expired"
            );
            let original = match &request.join_context {
                CallMediaJoinContext::Refresh(context) => &context.participant_id,
                _ => anyhow::bail!("recovery did not resolve the accepted participant"),
            };
            let response: arkret_models_collaboration::objects::media::CallMediaTokenExchangeOutcome = serde_json::from_value(
                cotest::harness::expect_json(holder.client.post("/_arkret/self/rtc/token").json(&request), reqwest::StatusCode::OK).await?
            )?;
            media_verification::verify_actual_outcome(holder, &request, &response).await?;
            ensure!(
                response.actor_id == request.actor_id
                    && response.device_id == request.device_id
                    && &response.participant_id == original,
                "restart changed the exact subject or accepted media leg"
            );
        }
        eprintln!(
            "[consent-call] phase=post_restart_refresh accepted_legs=2 stable_subjects=2 rotated={after_rotation} original_bindings_expired=2"
        );
        Ok(())
    }

    fn verify_service_signer_rotation(&self) -> bool {
        true
    }
}

#[async_trait::async_trait(?Send)]
impl MlsClientObserver for CallAdmissionObserver {
    fn verify_invite_delivery_race(&self) -> bool {
        true
    }

    async fn observe_ordinary_call_invite(
        &self,
        sender: &Member,
        holder: &Member,
        station: &cotest::harness::ArkretServer,
        realm: &arkret_wire::RealmId,
        accepted_group: &arkret_wire::EventId,
        sender_group: &mut arkret::ArkretMlsGroup,
        holder_group: &arkret::ArkretMlsGroup,
        observe_receipt: bool,
    ) -> Result<()> {
        CallAdmissionObserver::observe_ordinary_call_invite(
            self,
            sender,
            holder,
            station,
            station,
            realm,
            accepted_group,
            sender_group,
            holder_group,
            observe_receipt,
            None,
        )
        .await
    }
    async fn after_station_restart(&self, holder: &Member) -> Result<()> {
        CallAdmissionObserver::after_station_restart(self, holder).await
    }
    fn media_token_ttl_seconds(&self) -> Option<u64> {
        Some(30)
    }
    fn verify_service_signer_rotation(&self) -> bool {
        CallAdmissionObserver::verify_service_signer_rotation(self)
    }
}

#[async_trait::async_trait]
impl cotest::scenarios::message_mls_cross_station_live::CrossStationCallObserver
    for CallAdmissionObserver
{
    fn configure_emission_probe(&self, path: &std::path::Path) -> Result<()> {
        *self
            .emission_probe
            .lock()
            .map_err(|_| anyhow::anyhow!("emission probe lock poisoned"))? = Some(path.to_owned());
        Ok(())
    }
    async fn observe_ordinary_call_invite(
        &self,
        sender: &Member,
        holder: &Member,
        station: &cotest::harness::ArkretServer,
        holder_station: &cotest::harness::ArkretServer,
        realm: &arkret_wire::RealmId,
        accepted_group: &arkret_wire::EventId,
        sender_group: &mut arkret::ArkretMlsGroup,
        holder_group: &arkret::ArkretMlsGroup,
        other_holder: &Member,
        other_group: &arkret::ArkretMlsGroup,
        observe_receipt: bool,
    ) -> Result<()> {
        CallAdmissionObserver::observe_ordinary_call_invite(
            self,
            sender,
            holder,
            station,
            holder_station,
            realm,
            accepted_group,
            sender_group,
            holder_group,
            observe_receipt,
            Some((other_holder, other_group)),
        )
        .await
    }
    async fn observe_material_recovery(
        &self,
        sender: &Member,
        holder: &Member,
        realm: &arkret_wire::RealmId,
        accepted_group: &arkret_wire::EventId,
        sender_group: &arkret::ArkretMlsGroup,
        holder_group: &arkret::ArkretMlsGroup,
        control: cotest::harness::ScanGapControl,
    ) -> Result<()> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()?
                        .block_on(Box::pin(material_recovery::run(
                            sender,
                            holder,
                            realm,
                            accepted_group,
                            sender_group,
                            holder_group,
                            control,
                        )))
                })
                .join()
                .map_err(|_| anyhow::anyhow!("material recovery worker panicked"))?
        })
    }
    async fn after_station_restart(&self, holder: &Member) -> Result<()> {
        CallAdmissionObserver::after_station_restart(self, holder).await
    }
    fn media_token_ttl_seconds(&self) -> Option<u64> {
        Some(30)
    }
    fn verify_service_signer_rotation(&self) -> bool {
        CallAdmissionObserver::verify_service_signer_rotation(self)
    }
}

async fn grant(holder: &Member, peer: &ActorId, scope: ConsentScope) -> Result<PermissionGrant> {
    grant_payload(holder, peer, super::consent_support::permission(scope)).await
}
async fn grant_payload(
    holder: &Member,
    peer: &ActorId,
    permission: ConsentPermission,
) -> Result<PermissionGrant> {
    grant_payload_record(holder, peer, permission)
        .await
        .map(|(view, _)| view)
}
async fn grant_payload_record(
    holder: &Member,
    peer: &ActorId,
    permission: ConsentPermission,
) -> Result<(PermissionGrant, EventAdmissionSubmission)> {
    super::consent_support::grant(holder, peer, vec![permission]).await
}
async fn revoke(holder: &Member, grant: &PermissionGrant) -> Result<()> {
    revoke_record(holder, grant).await.map(|_| ())
}
async fn revoke_record(
    holder: &Member,
    grant: &PermissionGrant,
) -> Result<(ConsentView, EventAdmissionSubmission)> {
    super::consent_support::revoke(holder, grant).await
}

async fn exercise_token_invitation_mismatches(
    sender: &Member,
    holder: &Member,
    original: &arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
) -> Result<()> {
    for mutation in [
        "inviter_station",
        "holder",
        "scope",
        "call",
        "media",
        "signer",
        "ciphertext",
        "subject_device",
    ] {
        let mut request = original.clone();
        let CallMediaJoinContext::Invitation(context) = &mut request.join_context else {
            anyhow::bail!("actual first join must retain its original Invitation");
        };
        match mutation {
            "inviter_station" => {
                let mut account = sender.account.clone();
                account.station_id = "ak:did_core:web:other-station.example".parse()?;
                context.invitation.inviter_actor_id = ActorId::account(account);
            }
            "holder" => context.invitation.holder_account_id = sender.account.clone(),
            "scope" => {
                context.invitation.scope_ref = ScopeRef::Realm {
                    realm_id: arkret_wire::RealmId::from_event_id(&sender.authorize_event_id),
                }
            }
            "call" => {
                context.invitation.call_id =
                    arkret_wire::CallId::from_event_id(&sender.authorize_event_id)
            }
            "media" => {
                context.invitation.media.audio = false;
                context.invitation.media.video = true;
            }
            "signer" => context.invitation.proof.verification_method = holder.method.to_string(),
            "ciphertext" => {
                let mut bytes = arkret_canonical::base64url_decode(
                    &context.envelope.encrypted_payload.ciphertext,
                )?;
                let first = bytes
                    .first_mut()
                    .context("actual producer ciphertext is nonempty")?;
                *first ^= 1;
                context.envelope.encrypted_payload.ciphertext =
                    arkret_canonical::base64url_encode(bytes);
            }
            "subject_device" => request.device_id = sender.device.clone(),
            _ => unreachable!(),
        }
        // Keep the relation signature valid so a changed coordinate cannot be
        // mistaken for a plain signature-failure test. The frozen Signal proof
        // is retained, including the ciphertext mutation negative.
        arkret_signatures::call_invitation::sign_call_invitation(
            &mut context.invitation,
            &sender.key,
        )?;
        let broken_envelope_relation = matches!(
            mutation,
            "inviter_station" | "scope" | "signer" | "ciphertext"
        );
        let invalid_parameter = broken_envelope_relation || mutation == "subject_device";
        let problem = cotest::harness::expect_json(
            holder.client.post("/_arkret/self/rtc/token").json(&request),
            if invalid_parameter {
                reqwest::StatusCode::BAD_REQUEST
            } else {
                reqwest::StatusCode::CONFLICT
            },
        )
        .await
        .with_context(|| {
            format!(
                "actual Invitation token did not reject changed {mutation} at its contract boundary"
            )
        })?;
        ensure!(
            problem["type"]
                == if invalid_parameter {
                    "https://arkret.org/problems/param_invalid"
                } else {
                    "https://arkret.org/problems/failed_precondition"
                },
            "changed {mutation} hit another boundary"
        );
        if !invalid_parameter {
            ensure!(
                problem["detail"].as_str().is_some_and(
                    |s| s.contains("invitation is not this exact first-contact request")
                ),
                "changed {mutation} did not fail the first-contact binding"
            );
        }
        if broken_envelope_relation {
            ensure!(
                problem["detail"].as_str().is_some_and(
                    |s| s.contains("call invitation does not bind its exact producer envelope")
                ),
                "changed {mutation} did not fail the exact encrypted relation"
            );
        }
    }
    eprintln!("[consent-call] actual_token_relation_mismatches=8 token_releases=0");
    Ok(())
}

async fn token_status(
    holder: &Member,
    request: &arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
    status: reqwest::StatusCode,
) -> Result<()> {
    cotest::harness::expect_json(
        holder.client.post("/_arkret/self/rtc/token").json(request),
        status,
    )
    .await?;
    Ok(())
}

async fn token_precondition(
    member: &Member,
    request: &arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
    detail: &str,
) -> Result<()> {
    let problem = cotest::harness::expect_json(
        member.client.post("/_arkret/self/rtc/token").json(request),
        reqwest::StatusCode::CONFLICT,
    )
    .await?;
    ensure!(
        problem["type"] == "https://arkret.org/problems/failed_precondition"
            && problem["detail"]
                .as_str()
                .is_some_and(|s| s.contains(detail)),
        "token rejected outside its exact current participant precondition: {problem}"
    );
    Ok(())
}

async fn run_at_accepted_mls(
    sender: &Member,
    holder: &Member,
    station: &cotest::harness::ArkretServer,
    holder_station: &cotest::harness::ArkretServer,
    realm: &arkret_wire::RealmId,
    accepted_group: &arkret_wire::EventId,
    sender_group: &arkret::ArkretMlsGroup,
    holder_group: &arkret::ArkretMlsGroup,
    emission_probe: Option<&std::path::Path>,
    other_holder: Option<(&Member, &arkret::ArkretMlsGroup)>,
) -> Result<
    Vec<(
        arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
        chrono::DateTime<chrono::Utc>,
    )>,
> {
    use cotest::scenarios::human_device_producer_live::{
        grant_realm_actions, submit_and_expect_commit,
    };
    for member in [sender, holder] {
        grant_realm_actions(
            &sender.client,
            station,
            realm.as_str(),
            &member.account,
            &[
                arkret_wire::CapabilityActionId::CALL_JOIN,
                arkret_wire::CapabilityActionId::CALL_SIGNAL_SEND,
            ],
        )
        .await?;
    }
    let endpoint = holder
        .client
        .sdk()
        .base_url()
        .join("/_arkret/self/rtc/token")?
        .to_string();
    let media: RealmMediaServicePayload = serde_json::from_value(
        serde_json::json!({"value":{"service_id":holder.account.station_id,"foci":[{"focus_id":"consent-native","focus_kind":"arkret_native","token_endpoint":endpoint,"connect_url":holder.client.sdk().base_url().to_string()}]}}),
    )?;
    media.validate()?;
    let event = sender
        .client
        .author_event(
            realm.as_str(),
            EventKind::RealmMediaService.as_str(),
            serde_json::to_value(media)?,
        )
        .await?;
    submit_and_expect_commit(
        &sender.client,
        &sender.account,
        sender.device.as_str(),
        &event,
    )
    .await?;
    cotest::scenarios::human_device_producer_live::wait_for_committed(
        &holder.client,
        &event.event_id,
    )
    .await
    .context("holder Station must receive the accepted media binding before native catch-up")?;
    eprintln!("[consent-call] phase=accepted_media_service");
    let directory = tempfile::tempdir()?;
    let sender_host = Box::pin(native_call_endpoint(
        sender,
        realm,
        accepted_group,
        sender_group,
        &directory.path().join("sender.json"),
    ))
    .await?;
    eprintln!("[consent-call] phase=sender_native_host");
    let holder_host = Box::pin(native_call_endpoint(
        holder,
        realm,
        accepted_group,
        holder_group,
        &directory.path().join("holder.json"),
    ))
    .await?;
    eprintln!("[consent-call] phase=holder_native_host");
    let other_host = if let Some((other, group)) = other_holder {
        Some(
            native_call_endpoint(
                other,
                realm,
                accepted_group,
                group,
                &directory.path().join("other.json"),
            )
            .await?,
        )
    } else {
        None
    };

    run_call_cases(
        sender,
        holder,
        holder_station,
        realm,
        &sender_host,
        &holder_host,
        other_holder,
        other_host.as_ref(),
        emission_probe,
    )
    .await
}

#[inline(never)]
fn run_call_cases<'a>(
    sender: &'a Member, holder: &'a Member,
    holder_station: &'a cotest::harness::ArkretServer,
    realm: &'a arkret_wire::RealmId,
    sender_host: &'a inkson::sync_engine::NativeAccountHost,
    holder_host: &'a inkson::sync_engine::NativeAccountHost,
    other_holder: Option<(&'a Member, &'a arkret::ArkretMlsGroup)>,
    other_host: Option<&'a inkson::sync_engine::NativeAccountHost>,
    emission_probe: Option<&'a std::path::Path>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<(
    arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
    chrono::DateTime<chrono::Utc>,
)>>> + 'a>>{
    Box::pin(async move {
        use cotest::scenarios::human_device_producer_live::submit_and_expect_commit;
        let mut receiver = garth::signal::SignalReceiver::new();
        let mut refreshes = Vec::new();
        for (sequence, video) in [(1, false), (2, true)] {
            let (granted, original_grant) = grant_payload_record(
                holder,
                &sender.actor,
                ConsentPermission {
                    consent_scope: if video {
                        ConsentScope::VideoCall
                    } else {
                        ConsentScope::VoiceCall
                    },
                    not_before: None,
                    expires_at: None,
                    constraints: None,
                    evidence_ref: None,
                    reason: None,
                },
            )
            .await?;
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
            cotest::scenarios::human_device_producer_live::wait_for_committed(
                &holder.client,
                &create.event_id,
            )
            .await
            .context(
                "holder Station must receive the original accepted Call before native catch-up",
            )?;
            let call = arkret_wire::CallId::from_event_id(&create.event_id);
            sender_host
                .catch_up_selected_realm_until_complete(realm)
                .await?;
            holder_host
                .catch_up_selected_realm_until_complete(realm)
                .await?;
            let payload = inkson::signal::SignalPayload::CallSignal {
                call_id: call.clone(),
                seq: sequence,
                signal: arkret::CallSignalData::Invite(arkret::CallInviteSignalData {
                    lifetime_ms: 60_000,
                    offer: arkret::SessionDescription {
                        sdp_type: arkret::SessionDescriptionType::Offer,
                        sdp: "v=0".into(),
                    },
                    media: arkret::CallMediaSelection {
                        audio: true,
                        video,
                        screen: Some(false),
                    },
                }),
            };
            let mut stream = ready_signal_rail(holder).await?;
            let material = inkson::signal::key_material_for_scope(
                &sender_host.state_store(),
                realm.as_str(),
                None,
            )?;
            let _signer = ActiveEndpointSigner::install(sender)?;
            let outcome = sender_host
                .send_call_invitation(
                    holder.account.clone(),
                    ScopeRef::Realm {
                        realm_id: realm.clone(),
                    },
                    &material,
                    &payload,
                )
                .await?;
            ensure!(
                outcome.status == CallInvitationSendStatus::Deferred,
                "inviter received private admission state"
            );
            eprintln!("[consent-call] phase=sent_invitation video={video}");
            let received =
                next_admitted_signal(&mut stream, &holder_host, holder, &mut receiver).await?;
            let garth::signal::SignalReceiveOutcome::Accepted {
                call_invitation: Some(delivery),
                ..
            } = &received
            else {
                anyhow::bail!("holder did not receive actual product admission");
            };
            eprintln!("[consent-call] phase=decrypted_invitation video={video}");
            ensure!(
                delivery.outcome.admitted
                    && delivery.invitation.call_id == call
                    && delivery.invitation.holder_account_id == holder.account,
                "product cut differs from exact holder/Call"
            );
            let join = CallMediaJoinContext::Invitation(CallInvitationJoinContext {
                kind: CallInvitationJoinKind::Invitation,
                invitation: delivery.invitation.clone(),
                envelope: delivery.request.envelope.clone(),
            });
            let mut ordinary_payload = payload.clone();
            let inkson::signal::SignalPayload::CallSignal { seq, .. } = &mut ordinary_payload
            else {
                anyhow::bail!("ordinary control requires the actual Invite payload");
            };
            *seq += 1000;
            let ordinary_envelope = sender_host
                .prepare_signal_envelope(
                    ScopeRef::Realm {
                        realm_id: realm.clone(),
                    },
                    &material,
                    &ordinary_payload,
                )
                .await?;
            sender.client.sdk().signal_send(&ordinary_envelope).await?;
            let ordinary = next_admitted_signal(
                &mut stream,
                &holder_host,
                holder,
                &mut garth::signal::SignalReceiver::new(),
            )
            .await?;
            ensure!(
                matches!(
                    &ordinary,
                    garth::signal::SignalReceiveOutcome::Accepted {
                        call_invitation: None,
                        ..
                    }
                ),
                "ordinary encrypted rail acquired product admission material"
            );
            ensure!(
                inkson::conformance::observe_native_call_projection(&holder_host, ordinary).await?
                    == 0,
                "ordinary encrypted Invite entered the ringing product"
            );
            media_verification::reject_changed_admission_requests(sender, &holder_host, &received)
                .await?;
            ensure!(
                inkson::conformance::observe_native_call_projection(&holder_host, received.clone())
                    .await?
                    == 1,
                "valid full current did not reach the native ringing product"
            );
            drop(stream);
            let request =
                arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody {
                    realm_id: realm.clone(),
                    call_id: call.clone(),
                    actor_id: holder.actor.clone(),
                    device_id: holder.device.clone(),
                    focus_id: "consent-native".into(),
                    capability_refs: Vec::new(),
                    desired_media: Some(
                        arkret_models_collaboration::objects::media::CallMediaDesiredMedia {
                            audio: Some(true),
                            video: Some(video),
                            screen: Some(false),
                        },
                    ),
                    join_context: join,
                };
            let binding = media_verification::binding(holder, realm).await?;
            let response: arkret_models_collaboration::objects::media::CallMediaTokenExchangeOutcome =
            serde_json::from_value(
                cotest::harness::expect_json(
                    holder.client.post("/_arkret/self/rtc/token").json(&request),
                    reqwest::StatusCode::OK,
                )
                .await?,
            )?;
            ensure!(
                response.call_id == call
                    && response.actor_id == holder.actor
                    && response.device_id == holder.device
                    && !response.participant_binding.sig.is_empty(),
                "actual media token did not bind the holder participant"
            );
            media_verification::verify(holder, &request, &response, &binding).await?;
            exercise_token_invitation_mismatches(sender, holder, &request).await?;
            let mut refresh = request.clone();
            refresh.join_context = CallMediaJoinContext::Refresh(CallRefreshJoinContext {
                kind: CallRefreshJoinKind::Refresh,
                participant_id: response.participant_id.clone(),
            });
            token_precondition(
                holder,
                &refresh,
                "refresh has no active accepted participant for this exact actor/device",
            )
            .await
            .context("unestablished refresh must not bypass first-contact admission")?;
            media_verification::verify_actual_outcome(holder, &request, &response).await?;
            ensure!(
                response.actor_id == holder.actor && response.device_id == holder.device,
                "durable roster coordinates differ from the authenticated full subject"
            );
            let established = holder.client.author_event(
            realm.as_str(), EventKind::CallState.as_str(),
            serde_json::to_value(arkret_models_collaboration::events_payloads::call::CallStatePayload {
                call_id: call.clone(), state_transition: None,
                focus: Some(arkret_models_collaboration::events_payloads::call::CallFocus {
                    mode: arkret_models_collaboration::events_payloads::call::CallMode::Sfu,
                    session_focus: Some(arkret_wire::NonEmptyString::new("consent-native")
                        .map_err(anyhow::Error::msg)?),
                }),
                recording_transition: None, transcript_transition: None,
                roster_delta: Some(arkret_models_collaboration::events_payloads::call::CallRosterDelta::Join {
                    participant: arkret_models_collaboration::events_payloads::call::CallParticipant {
                        actor_id: response.actor_id.clone(), device_id: response.device_id.to_string(),
                        joined_at: None, foci_preferred: None,
                        participant_id: Some(response.participant_id.clone()),
                        participant_binding: Some(serde_json::from_value(
                            serde_json::to_value(&response.participant_binding)?)?),
                        media: Some(arkret_models_collaboration::events_payloads::call::CallParticipantMedia {
                            audio: Some(true), video: Some(video), screen: Some(false),
                        }), focus_id: Some("consent-native".into()),
                    },
                }), moderation_delta: None, mute_override: None,
            })?,
        ).await?;
            submit_and_expect_commit(
                &holder.client,
                &holder.account,
                holder.device.as_str(),
                &established,
            )
            .await?;
            token_status(holder, &refresh, reqwest::StatusCode::OK)
                .await
                .context("accepted same actor/device participant must refresh")?;
            exercise_complete_roster_leave_and_rejoin(holder, realm, &call, &established, &refresh)
                .await?;
            for original in [&request, &refresh] {
                let mut expanded = original.clone();
                expanded
                    .desired_media
                    .as_mut()
                    .context("explicit accepted media")?
                    .screen = Some(true);
                let detail = match &expanded.join_context {
                    CallMediaJoinContext::Invitation(_) => {
                        "invitation is not this exact first-contact request"
                    }
                    _ => "refresh exceeds the accepted signed media range",
                };
                token_precondition(holder, &expanded, detail).await?;
            }

            for mutation in ["participant", "focus", "call"] {
                let mut invalid = refresh.clone();
                match mutation {
                    "participant" => {
                        if let CallMediaJoinContext::Refresh(context) = &mut invalid.join_context {
                            context.participant_id =
                                "ak:rtc_participant:01964137-0000-7000-8000-00000000dead".into();
                        }
                    }
                    "focus" => invalid.focus_id = "another-focus".into(),
                    "call" => {
                        invalid.call_id =
                            "ak:call:ARzVic5s2NUShp82C8GPo-shbkm7isUWyvILLThc3aNL".parse()?
                    }
                    _ => unreachable!(),
                }
                let expected = if mutation == "call" {
                    reqwest::StatusCode::FORBIDDEN
                } else {
                    reqwest::StatusCode::CONFLICT
                };
                token_status(holder, &invalid, expected).await?;
            }
            if !video {
                let mut expanded = request.clone();
                expanded
                    .desired_media
                    .as_mut()
                    .context("explicit media")?
                    .video = Some(true);
                token_precondition(
                    holder,
                    &expanded,
                    "invitation is not this exact first-contact request",
                )
                .await
                .context("voice invitation must not authorize video expansion")?;
            }
            let older =
                inkson::conformance::read_native_call_consent(&holder_host, &delivery.invitation)
                    .await?;
            let (revoked, original_revoke) = revoke_record(holder, &granted).await?;
            let fresh =
                inkson::conformance::read_native_call_consent(&holder_host, &delivery.invitation)
                    .await?;
            let revoked_head = fresh.source().value()?.effective_stream_head.clone();
            let generation = fresh.authority_generation()?;
            let delayed = older
                .permits(
                    Some(generation),
                    std::slice::from_ref(&revoked_head),
                    chrono::Utc::now(),
                )
                .expect_err("older actual full read authorized after a known revoke");
            ensure!(
                delayed
                    .to_string()
                    .contains("rolls back a known current cut"),
                "delayed full read failed at another boundary: {delayed}"
            );
            for (path, submitted, original) in [
                (
                    "/_arkret/self/consent/results/replace",
                    serde_json::to_value(ConsentReplaceRequestBody {
                        consent_event: original_grant,
                    })?,
                    &granted.view,
                ),
                (
                    "/_arkret/self/consent/results/replace",
                    serde_json::to_value(ConsentReplaceRequestBody {
                        consent_event: original_revoke,
                    })?,
                    &revoked,
                ),
            ] {
                let replay = cotest::harness::expect_json(
                    holder.client.post(path).json(&submitted),
                    reqwest::StatusCode::OK,
                )
                .await?;
                ensure!(
                    replay == serde_json::to_value(original)?,
                    "exact retry changed its original accepted outcome"
                );
            }
            let after_retry =
                inkson::conformance::read_native_call_consent(&holder_host, &delivery.invitation)
                    .await?;
            let current = after_retry.source().value()?;
            ensure!(
                current.effective_stream_head == revoked_head,
                "exact retries allocated another Commit"
            );
            ensure!(
                matches!(&current.current,arkret_models_collaboration::consent_operations::ConsentCurrentState::Present{result} if result.selector.peer_id==*revoked.peer.actor_id() && result.revision==revoked.revision && !result.value.permissions.iter().any(|p|p.consent_scope==if video{ConsentScope::VideoCall}else{ConsentScope::VoiceCall})),
                "exact retry rolled authoritative current back from its accepted revoke"
            );
            eprintln!(
                "[consent-call] video={video} original_grant_revoke_retries=2 new_commits=0 actual_older_read_rejected=1"
            );
            ensure!(
                inkson::conformance::observe_native_call_projection(&holder_host, received.clone())
                    .await?
                    == 0,
                "previous product admission rang after accepted revoke"
            );
            token_status(holder, &request, reqwest::StatusCode::FORBIDDEN)
                .await
                .context("previous product admission minted a token after accepted revoke")?;
            token_status(holder, &refresh, reqwest::StatusCode::OK)
                .await
                .context("Consent revoke must not end an accepted established leg")?;
            refreshes.push((refresh, response.participant_binding.expires_at));
            cotest::harness::heap_future(|| async {
            for (offset, window) in ["future", "expired", "unknown_constraint"]
                .into_iter()
                .enumerate()
            {
                let now = chrono::Utc::now();
                let consent_payload = ConsentPermission {
                    consent_scope: if video {ConsentScope::VideoCall} else {ConsentScope::VoiceCall},
                    not_before: (window == "future").then_some(now + chrono::Duration::hours(1)),
                    expires_at: (window == "expired").then_some(now - chrono::Duration::hours(1)),
                    constraints: (window == "unknown_constraint").then(|| {
                        vec![
                            [("unrecognized".into(), serde_json::json!(true))]
                                .into_iter()
                                .collect(),
                        ]
                    }),
                    evidence_ref: None,
                    reason: None,
                };
                grant_payload(holder, &sender.actor, consent_payload).await?;
                let (fresh_invitation, ineligible) = fresh_call_signal(
                    (sender_host, sender),
                    holder_host,
                    holder,
                    realm,
                    &material,
                    &payload,
                    10 + offset as u64,
                )
                .await?;
                let mut ineligible_request = request.clone();
                ineligible_request.join_context = invitation_context(&fresh_invitation);
                token_status(holder, &ineligible_request, reqwest::StatusCode::FORBIDDEN)
                    .await
                    .with_context(|| {
                        format!("{window} Consent authorized the actual invitation token cut")
                    })?;
                ensure!(
                    inkson::conformance::observe_native_call_projection(&holder_host, ineligible)
                        .await?
                        == 0,
                    "ineligible Consent authorized ringing"
                );
            }
            let concrete_scope = if video {
                ConsentScope::VideoCall
            } else {
                ConsentScope::VoiceCall
            };
            let invite_permission = grant(holder, &sender.actor, ConsentScope::Invite).await?;
            let _concrete = grant(holder, &sender.actor, concrete_scope).await?;
            revoke(holder, &invite_permission).await?;
            let (fresh_invitation, concrete_signal) = fresh_call_signal(
                (sender_host, sender),
                holder_host,
                holder,
                realm,
                &material,
                &payload,
                13,
            )
            .await?;
            let mut concrete_request = request.clone();
            concrete_request.join_context = invitation_context(&fresh_invitation);
            token_status(holder, &concrete_request, reqwest::StatusCode::OK)
                .await
                .context("removing Invite erased retained call Consent")?;
            ensure!(
                inkson::conformance::observe_native_call_projection(&holder_host, concrete_signal)
                    .await?
                    == 1,
                "removing Invite erased retained call ringing admission"
            );
            let unrelated=grant(holder,&sender.actor,ConsentScope::Presence).await?;
            let remaining_call=grant(holder,&sender.actor,concrete_scope).await?;
            revoke(holder,&unrelated).await?;
            let (fresh_invitation, retained_call_signal) = fresh_call_signal(
                (sender_host, sender),
                holder_host,
                holder,
                realm,
                &material,
                &payload,
                14,
            )
            .await?;
            let mut retained_call_request = request.clone();
            retained_call_request.join_context = invitation_context(&fresh_invitation);
            token_status(holder, &retained_call_request, reqwest::StatusCode::OK)
                .await
                .context("removing Presence erased retained call Consent")?;
            ensure!(
                inkson::conformance::observe_native_call_projection(
                    &holder_host,
                    retained_call_signal.clone()
                )
                .await?
                    == 1,
                "removing Presence erased retained call ringing admission"
            );
            revoke(holder, &remaining_call).await?;
            token_status(holder, &retained_call_request, reqwest::StatusCode::FORBIDDEN).await?;
            let garth::signal::SignalReceiveOutcome::Accepted {
                call_invitation: Some(product),
                ..
            } = &retained_call_signal
            else {
                anyhow::bail!("fresh retained call control omitted its product verdict");
            };
            ensure!(
                product.outcome.expires_at > chrono::Utc::now(),
                "revocation control crossed its original product window"
            );
            ensure!(
                inkson::conformance::observe_native_call_projection(&holder_host, retained_call_signal)
                    .await?
                    == 0,
                "removed call scope remained eligible through an older product outcome"
            );
            eprintln!(
                "[consent-call] video={video} ineligible_windows=3 unrelated_scope_removals=2 all_revoked_denied=1"
            );
            Ok::<(), anyhow::Error>(())
            }).await?;
            let now = chrono::Utc::now();
            let mut intent_nonce = [0u8; 32];
            getrandom::fill(&mut intent_nonce)?;
            let mut voluntary = request.clone();
            voluntary.join_context = CallMediaJoinContext::Voluntary(CallVoluntaryJoinContext {
                kind: CallVoluntaryJoinKind::Voluntary,
                created_at: now,
                expires_at: now + chrono::Duration::seconds(60),
                nonce: arkret_canonical::base64url_encode(intent_nonce),
                proof: CallVoluntaryJoinProof {
                    verification_method: holder.method.to_string(),
                    jws: String::new(),
                },
            });
            arkret_signatures::call_invitation::sign_call_voluntary_join(
                &mut voluntary,
                &holder.key,
            )?;
            token_status(holder, &voluntary, reqwest::StatusCode::OK)
                .await
                .context("actual affirmative signed voluntary join must remain legal")?;
            if let (Some((other, _)), Some(other_host)) = (other_holder, &other_host) {
                exercise_independent_holder(
                    sender,
                    holder,
                    other,
                    &sender_host,
                    other_host,
                    realm,
                    &material,
                    &payload,
                    &received,
                    &request,
                )
                .await?;
            }
            if video {
                if let Some(probe) = emission_probe {
                    token_release::run(
                        sender,
                        holder,
                        &sender_host,
                        realm,
                        &material,
                        &payload,
                        probe,
                    )
                    .await?;
                    exercise_inflight_product_revoke(
                        sender,
                        holder,
                        holder_station,
                        &sender_host,
                        &holder_host,
                        realm,
                        &call,
                        &material,
                        &payload,
                        probe,
                    )
                    .await?;
                }
            }
            if video {
                exercise_decrypted_relation_mismatches(
                    sender,
                    holder,
                    &sender_host,
                    &holder_host,
                    realm,
                    &refreshes[0].0.call_id,
                    &material,
                    &payload,
                )
                .await?;
            }
            eprintln!(
                "[consent-call] video={video} product=1 ringing=1 token=1 revoked_ring=0 revoked_token=0 unestablished_refresh=0 established_refresh=1 full_actor_roster=1 revoked_refresh=1 voluntary=1"
            );
        }
        Ok(refreshes)
    })
}

async fn fresh_call_signal(
    producer: (&inkson::sync_engine::NativeAccountHost, &Member),
    consumer: &inkson::sync_engine::NativeAccountHost,
    holder: &Member,
    realm: &arkret_wire::RealmId,
    material: &inkson::signal::SignalKeyMaterial,
    original: &inkson::signal::SignalPayload,
    sequence: u64,
) -> Result<(
    CallInvitationSendRequestBody,
    garth::signal::SignalReceiveOutcome,
)> {
    let mut payload = original.clone();
    let inkson::signal::SignalPayload::CallSignal { seq, .. } = &mut payload else {
        anyhow::bail!("fresh control requires the original Invite payload");
    };
    *seq = sequence;
    let mut rail = ready_signal_rail(holder).await?;
    let request = producer
        .0
        .prepare_call_invitation(
            holder.account.clone(),
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            material,
            &payload,
        )
        .await?;
    let sent = producer
        .1
        .client
        .sdk()
        .call_invitation_send(&request)
        .await?;
    ensure!(sent.status == CallInvitationSendStatus::Deferred);
    let received = next_admitted_signal(
        &mut rail,
        consumer,
        holder,
        &mut garth::signal::SignalReceiver::new(),
    )
    .await?;
    Ok((request, received))
}

fn invitation_context(request: &CallInvitationSendRequestBody) -> CallMediaJoinContext {
    CallMediaJoinContext::Invitation(CallInvitationJoinContext {
        kind: CallInvitationJoinKind::Invitation,
        invitation: request.invitation.clone(),
        envelope: request.envelope.clone(),
    })
}

async fn probe_observation(path: &std::path::Path) -> Result<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Ok(bytes) = tokio::fs::read(path).await {
            if let Ok(value) = serde_json::from_slice(&bytes) {
                return Ok(value);
            }
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "actual Call frame never reached the probe"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

enum ProductRail {
    Http(arkret_http_client::SignalSubscribeFrameStream),
    WebSocket(cotest::scenarios::websocket_live::LiveSignalReader),
}

impl ProductRail {
    async fn next_frame(
        &mut self,
    ) -> Result<Option<arkret_models_collaboration::SignalStreamFrame>> {
        match self {
            Self::Http(rail) => Ok(rail.next_frame().await?),
            Self::WebSocket(rail) => rail.next_frame().await,
        }
    }
}

async fn next_product_frame(
    rail: &mut ProductRail,
    expected: &arkret_wire::SignalEnvelope,
) -> Result<(
    arkret_wire::SignalEnvelope,
    arkret_models_collaboration::SignalDeliveryAuthority,
)> {
    let original = arkret_canonical::canonical_json_bytes(expected)?;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match rail
                .next_frame()
                .await?
                .context("actual product rail remains open")?
            {
                arkret_models_collaboration::SignalStreamFrame::Heartbeat => {}
                arkret_models_collaboration::SignalStreamFrame::Signal {
                    envelope,
                    delivery_authority,
                } => {
                    if envelope.proof.envelope_digest != expected.proof.envelope_digest {
                        continue;
                    }
                    ensure!(
                        arkret_canonical::canonical_json_bytes(&envelope)? == original,
                        "actual queued frame changed original ciphertext"
                    );
                    return Ok((envelope, delivery_authority));
                }
                control => anyhow::bail!("actual product rail control: {control:?}"),
            }
        }
    })
    .await?
}

#[expect(
    clippy::too_many_arguments,
    reason = "Exact live producer and receiver cuts"
)]
async fn exercise_inflight_product_revoke(
    sender: &Member,
    holder: &Member,
    holder_station: &cotest::harness::ArkretServer,
    producer: &inkson::sync_engine::NativeAccountHost,
    consumer: &inkson::sync_engine::NativeAccountHost,
    realm: &arkret_wire::RealmId,
    call: &arkret_wire::CallId,
    material: &inkson::signal::SignalKeyMaterial,
    original: &inkson::signal::SignalPayload,
    probe_file: &std::path::Path,
) -> Result<()> {
    for websocket in [false, true] {
        let granted = grant(holder, &sender.actor, ConsentScope::VideoCall).await?;
        for (sequence, deny) in [
            (if websocket { 103 } else { 101 }, false),
            (if websocket { 104 } else { 102 }, true),
        ] {
            producer
                .catch_up_selected_realm_until_complete(realm)
                .await?;
            let mut payload = original.clone();
            let inkson::signal::SignalPayload::CallSignal { seq, .. } = &mut payload else {
                anyhow::bail!("actual Invite payload");
            };
            *seq = sequence;
            let request = producer
                .prepare_call_invitation(
                    holder.account.clone(),
                    ScopeRef::Realm {
                        realm_id: realm.clone(),
                    },
                    material,
                    &payload,
                )
                .await?;
            let mut rail = if websocket {
                ProductRail::WebSocket(
                    cotest::scenarios::websocket_live::LiveSignalReader::connect_signal(
                        holder_station,
                        &holder.client,
                    )
                    .await?,
                )
            } else {
                ProductRail::Http(ready_signal_rail(holder).await?)
            };
            let selected = vec![(
                holder.account.clone(),
                request.envelope.proof.envelope_digest.clone(),
            )];
            let pause = probe_file.with_extension("0.pause");
            for extension in ["reached.json", "outcome.json"] {
                match std::fs::remove_file(pause.with_extension(extension)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            std::fs::write(
                probe_file,
                arkret_canonical::canonical_json_bytes(&selected)?,
            )?;
            std::fs::write(&pause, [])?;
            if websocket {
                std::fs::write(pause.with_extension("skip"), [])?;
            }
            ensure!(
                sender
                    .client
                    .sdk()
                    .call_invitation_send(&request)
                    .await?
                    .status
                    == CallInvitationSendStatus::Deferred
            );
            let actual: arkret_wire::SignalEnvelope = serde_json::from_value(
                probe_observation(&pause.with_extension("reached.json")).await?,
            )?;
            ensure!(
                arkret_canonical::canonical_json_bytes(&actual)?
                    == arkret_canonical::canonical_json_bytes(&request.envelope)?,
                "probe did not pause the original production ciphertext"
            );
            ensure!(
                chrono::Utc::now() + chrono::Duration::seconds(8) < request.envelope.expires_at,
                "paused original frame must remain live through revocation"
            );
            if deny {
                revoke(holder, &granted).await?;
            }
            std::fs::remove_file(&pause)?;
            let decision = probe_observation(&pause.with_extension("outcome.json")).await?;
            ensure!(
                decision["admitted"] == true
                    && decision["call_invitation"] == serde_json::json!(!deny),
                "actual final emission gate disagreed with current Consent"
            );
            let decided_at = chrono::DateTime::parse_from_rfc3339(
                decision["observed_at"]
                    .as_str()
                    .context("actual gate decision time")?,
            )?;
            ensure!(
                decided_at < request.envelope.expires_at
                    && chrono::Utc::now() + chrono::Duration::seconds(3)
                        < request.envelope.expires_at,
                "actual emission decision must precede original TTL expiry"
            );
            let (envelope, authority) = next_product_frame(&mut rail, &request.envelope).await?;
            ensure!(
                authority.call_invitation.is_some() == !deny,
                "physical ciphertext carried an incorrect product verdict"
            );
            let decryptor = inkson::signal_receive_engine::MlsSignalDecryptor::new(
                consumer.state_store_handle(),
                holder.account.clone(),
                holder.device.clone(),
            );
            let received = garth::signal::SignalReceiver::new()
                .receive(&envelope, &authority, &decryptor, chrono::Utc::now())
                .await?;
            ensure!(
                inkson::conformance::observe_native_call_projection(consumer, received).await?
                    == usize::from(!deny),
                "physical product cut disagreed with current Consent"
            );
        }
    }
    ensure!(
        call == match original {
            inkson::signal::SignalPayload::CallSignal { call_id, .. } => call_id,
            _ => unreachable!(),
        }
    );
    eprintln!(
        "[consent-call] inflight_product_positive=2 before_physical_frame_revoke_denied=2 original_ciphertext=1 http=1 websocket_queued=1"
    );
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Original accepted Call and real MLS endpoints"
)]
async fn exercise_decrypted_relation_mismatches(
    sender: &Member,
    holder: &Member,
    producer: &inkson::sync_engine::NativeAccountHost,
    consumer: &inkson::sync_engine::NativeAccountHost,
    realm: &arkret_wire::RealmId,
    other_call: &arkret_wire::CallId,
    material: &inkson::signal::SignalKeyMaterial,
    original: &inkson::signal::SignalPayload,
) -> Result<()> {
    let (granted, _) = super::consent_support::grant(
        holder,
        &sender.actor,
        vec![
            super::consent_support::permission(ConsentScope::VoiceCall),
            super::consent_support::permission(ConsentScope::VideoCall),
        ],
    )
    .await?;
    for (sequence, mismatch) in [(201, "media"), (202, "call"), (203, "kind")] {
        producer
            .catch_up_selected_realm_until_complete(realm)
            .await?;
        let mut payload = original.clone();
        let inkson::signal::SignalPayload::CallSignal { seq, .. } = &mut payload else {
            anyhow::bail!("real Invite payload");
        };
        *seq = sequence;
        let scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let mut request = producer
            .prepare_call_invitation(holder.account.clone(), scope.clone(), material, &payload)
            .await?;
        match mismatch {
            "media" => request.invitation.media.video = false,
            "call" => request.invitation.call_id = other_call.clone(),
            "kind" => {
                let inkson::signal::SignalPayload::CallSignal { signal, .. } = &mut payload else {
                    unreachable!()
                };
                *signal = arkret::CallSignalData::Answer(arkret::CallAnswerSignalData {
                    answer: arkret::SessionDescription {
                        sdp_type: arkret::SessionDescriptionType::Answer,
                        sdp: "v=0".into(),
                    },
                    accepted_media: arkret::CallMediaSelection {
                        audio: true,
                        video: true,
                        screen: Some(false),
                    },
                });
                request.envelope = producer
                    .prepare_signal_envelope(scope, material, &payload)
                    .await?;
                request.invitation.envelope_digest =
                    arkret_models_collaboration::call_invitation::call_invitation_envelope_digest(
                        &request.envelope,
                    )?;
                request.invitation.expires_at = request.envelope.expires_at;
            }
            _ => unreachable!(),
        }
        arkret_signatures::call_invitation::sign_call_invitation(
            &mut request.invitation,
            &sender.key,
        )?;
        let mut rail = ready_signal_rail(holder).await?;
        ensure!(
            sender
                .client
                .sdk()
                .call_invitation_send(&request)
                .await?
                .status
                == CallInvitationSendStatus::Deferred
        );
        let (envelope, delivery_authority) =
            next_exact_frame(&mut rail, &request.envelope)
                .await
                .with_context(|| format!("actual {mismatch} ciphertext delivery"))?;
        ensure!(
            delivery_authority.call_invitation.is_some(),
            "blind Station omitted product material for the actual signed relation"
        );
        let decryptor = inkson::signal_receive_engine::MlsSignalDecryptor::new(
            consumer.state_store_handle(),
            holder.account.clone(),
            holder.device.clone(),
        );
        let error = garth::signal::SignalReceiver::new()
            .receive(
                &envelope,
                &delivery_authority,
                &decryptor,
                chrono::Utc::now(),
            )
            .await
            .expect_err("decrypted relation mismatch reached the accepted product");
        let expected = if mismatch == "kind" {
            "call invitation plaintext is not Invite"
        } else {
            "call invitation plaintext differs from signed relation"
        };
        ensure!(
            error.to_string().contains(expected),
            "{mismatch} rejected before the required real decrypt comparison: {error}"
        );
        eprintln!("[consent-call] mismatch={mismatch} actual_decrypt_reject=1");
    }
    revoke(holder, &granted).await?;
    eprintln!("[consent-call] real_decrypted_media_call_kind_mismatches=3 accepted_products=0");
    Ok(())
}

async fn next_exact_frame(
    rail: &mut arkret_http_client::SignalSubscribeFrameStream,
    expected: &arkret_wire::SignalEnvelope,
) -> Result<(
    arkret_wire::SignalEnvelope,
    arkret_models_collaboration::SignalDeliveryAuthority,
)> {
    let original = arkret_canonical::canonical_json_bytes(expected)?;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match rail
                .next_frame()
                .await?
                .context("actual target rail remains open")?
            {
                arkret_models_collaboration::SignalStreamFrame::Heartbeat => {}
                arkret_models_collaboration::SignalStreamFrame::Signal {
                    envelope,
                    delivery_authority,
                } => {
                    if envelope.proof.envelope_digest != expected.proof.envelope_digest {
                        continue;
                    }
                    ensure!(
                        arkret_canonical::canonical_json_bytes(&envelope)? == original,
                        "actual target frame changed the original canonical ciphertext"
                    );
                    return Ok((envelope, delivery_authority));
                }
                control => anyhow::bail!("actual target rail control: {control:?}"),
            }
        }
    })
    .await?
}

/// The cursorless subscription must begin before publishing the observed frame.
/// HTTP headers alone do not prove that its stream-start cut has run.
async fn ready_signal_rail(
    holder: &Member,
) -> Result<arkret_http_client::SignalSubscribeFrameStream> {
    let mut rail = holder.client.sdk().signal_subscribe_frames().await?;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match rail
                .next_frame()
                .await?
                .context("actual subscriber readiness rail remains open")?
            {
                arkret_models_collaboration::SignalStreamFrame::Heartbeat => {
                    return Ok::<(), anyhow::Error>(());
                }
                arkret_models_collaboration::SignalStreamFrame::Signal { .. } => {}
                control => anyhow::bail!("actual subscription readiness control: {control:?}"),
            }
        }
    })
    .await
    .context("actual authenticated subscriber did not become ready")??;
    Ok(rail)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Independent actual holder credentials and MLS"
)]
async fn exercise_independent_holder(
    sender: &Member,
    granted: &Member,
    denied: &Member,
    producer: &inkson::sync_engine::NativeAccountHost,
    consumer: &inkson::sync_engine::NativeAccountHost,
    realm: &arkret_wire::RealmId,
    material: &inkson::signal::SignalKeyMaterial,
    payload: &inkson::signal::SignalPayload,
    granted_outcome: &garth::signal::SignalReceiveOutcome,
    granted_request: &arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
) -> Result<()> {
    ensure!(denied.actor != granted.actor && denied.device != granted.device);
    ensure!(
        inkson::conformance::observe_native_call_projection(consumer, granted_outcome.clone())
            .await?
            == 0,
        "another holder's real admitted outcome authorized the denied holder's product"
    );
    let mut token = granted_request.clone();
    token.actor_id = denied.actor.clone();
    token.device_id = denied.device.clone();
    token_precondition(
        denied,
        &token,
        "invitation is not this exact first-contact request",
    )
    .await?;
    let request = producer
        .prepare_call_invitation(
            denied.account.clone(),
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            material,
            payload,
        )
        .await?;
    let fresh =
        inkson::conformance::read_native_call_consent(consumer, &request.invitation).await?;
    ensure!(
        !fresh.permits(None, &[], chrono::Utc::now())?,
        "second holder unexpectedly had matching Consent"
    );
    let mut rail = ready_signal_rail(denied).await?;
    ensure!(
        sender
            .client
            .sdk()
            .call_invitation_send(&request)
            .await?
            .status
            == CallInvitationSendStatus::Deferred
    );
    let quiet = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match rail
                .next_frame()
                .await?
                .context("denied holder rail remains open")?
            {
                arkret_models_collaboration::SignalStreamFrame::Heartbeat => {}
                arkret_models_collaboration::SignalStreamFrame::Signal {
                    envelope,
                    delivery_authority,
                } => {
                    ensure!(
                        delivery_authority.call_invitation.is_none(),
                        "denied holder received call product material"
                    );
                    let decryptor = inkson::signal_receive_engine::MlsSignalDecryptor::new(
                        consumer.state_store_handle(),
                        denied.account.clone(),
                        denied.device.clone(),
                    );
                    let received = garth::signal::SignalReceiver::new()
                        .receive(
                            &envelope,
                            &delivery_authority,
                            &decryptor,
                            chrono::Utc::now(),
                        )
                        .await?;
                    ensure!(
                        matches!(
                            &received,
                            garth::signal::SignalReceiveOutcome::Accepted {
                                call_invitation: None,
                                ..
                            }
                        ),
                        "ordinary control did not reach actual decryption"
                    );
                    ensure!(
                        inkson::conformance::observe_native_call_projection(consumer, received)
                            .await?
                            == 0,
                        "ordinary encrypted control rang for the unconsenting holder"
                    );
                }
                _ => anyhow::bail!("denied holder rail terminated during product observation"),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    })
    .await;
    ensure!(
        quiet.is_err(),
        "second holder product was not withheld: {quiet:?}"
    );
    token.join_context = CallMediaJoinContext::Invitation(CallInvitationJoinContext {
        kind: CallInvitationJoinKind::Invitation,
        invitation: request.invitation.clone(),
        envelope: request.envelope.clone(),
    });
    token_status(denied, &token, reqwest::StatusCode::FORBIDDEN).await?;
    // Force an actual generic encrypted delivery to exercise this holder's
    // decryptor and native product, without manufacturing delivery material.
    let mut ordinary_payload = payload.clone();
    let inkson::signal::SignalPayload::CallSignal { seq, .. } = &mut ordinary_payload else {
        unreachable!()
    };
    *seq += 2000;
    let ordinary = producer
        .prepare_signal_envelope(
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            material,
            &ordinary_payload,
        )
        .await?;
    sender.client.sdk().signal_send(&ordinary).await?;
    let (envelope, authority) = next_exact_frame(&mut rail, &ordinary).await?;
    ensure!(
        authority.call_invitation.is_none(),
        "ordinary rail inherited another holder's product admission"
    );
    let decryptor = inkson::signal_receive_engine::MlsSignalDecryptor::new(
        consumer.state_store_handle(),
        denied.account.clone(),
        denied.device.clone(),
    );
    let received = garth::signal::SignalReceiver::new()
        .receive(&envelope, &authority, &decryptor, chrono::Utc::now())
        .await?;
    ensure!(
        inkson::conformance::observe_native_call_projection(consumer, received).await? == 0,
        "denied holder's actual decrypted Invite rang without product admission"
    );
    eprintln!(
        "[consent-call] independent_actual_holders=2 granted_product=1 denied_product=0 denied_token=0 borrowed_outcome_rejected=1"
    );
    Ok(())
}

async fn read_complete_roster(
    member: &Member,
    realm: &arkret_wire::RealmId,
    call: &arkret_wire::CallId,
    expected_source: &arkret_wire::EventId,
) -> Result<arkret_wire::CurrentRevision> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if let Ok(snapshot) = member.client.sdk().realm_state_snapshot_head(realm).await {
            for row in &snapshot.current_state_entries {
                let arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::CallRoster { call_id },
                    source_stream_ref,
                    revision,
                    value,
                } = row
                else {
                    continue;
                };
                if call_id != call {
                    continue;
                }
                let current: arkret_models_collaboration::events_payloads::call::CallRosterCurrentValue =
                    serde_json::from_value(value.clone())?;
                current.validate_for_axis(source_stream_ref, revision)?;
                if &current.last_source.source_commit.event_ref == expected_source {
                    arkret::verify_call_roster_bindings(realm, call, &current)?;
                    ensure!(
                        current.effective_participants()?.len() == 1,
                        "complete roster lost the active full-actor leg"
                    );
                    return Ok(revision.clone());
                }
            }
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "actual snapshot did not disclose the complete accepted Call roster"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

async fn exercise_complete_roster_leave_and_rejoin(
    member: &Member,
    realm: &arkret_wire::RealmId,
    call: &arkret_wire::CallId,
    established: &arkret_wire::Event,
    refresh: &arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
) -> Result<()> {
    use cotest::scenarios::human_device_producer_live::submit_and_expect_commit;
    read_complete_roster(member, realm, call, &established.event_id).await?;
    let payload = serde_json::to_value(&established.payload)?;
    let update = member
        .client
        .author_event(
            realm.as_str(),
            EventKind::CallState.as_str(),
            payload.clone(),
        )
        .await?;
    submit_and_expect_commit(
        &member.client,
        &member.account,
        member.device.as_str(),
        &update,
    )
    .await?;
    let revision = read_complete_roster(member, realm, call, &update.event_id).await?;
    let CallMediaJoinContext::Refresh(_) = &refresh.join_context else {
        anyhow::bail!("refresh context missing")
    };
    let leave = member
        .client
        .author_event(
            realm.as_str(),
            EventKind::CallState.as_str(),
            serde_json::json!({
                "call_id":call,"roster_delta":{"op":"leave",
                    "actor_id":member.actor,
                    "device_id":member.device,
                    "expected_revision":revision
                }
            }),
        )
        .await?;
    submit_and_expect_commit(
        &member.client,
        &member.account,
        member.device.as_str(),
        &leave,
    )
    .await?;
    token_precondition(
        member,
        refresh,
        "refresh has no active accepted participant for this exact actor/device",
    )
    .await
    .context("accepted leave must remove refresh permission")?;
    let rejoin = member
        .client
        .author_event(realm.as_str(), EventKind::CallState.as_str(), payload)
        .await?;
    submit_and_expect_commit(
        &member.client,
        &member.account,
        member.device.as_str(),
        &rejoin,
    )
    .await?;
    read_complete_roster(member, realm, call, &rejoin.event_id).await?;
    token_status(member, refresh, reqwest::StatusCode::OK)
        .await
        .context("fresh accepted rejoin must restore the same full-actor leg")?;
    eprintln!(
        "[consent-call] complete_roster_entries=1 exact_last_source=1 active_legs=1 accepted_leave_refresh_denied=1 rejoin_refresh=1"
    );
    Ok(())
}
