//! Native Applet custody, current review and a two-Station configuration route.
use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody;
use arkret_models_collaboration::governance::operation_wire::AppletPolicyTarget;
use arkret_models_integration::*;
use arkret_wire::{
    ActorId, ApprovalContext, ApprovalSignature, ApprovalSignatureInput, ApprovalSignatureProof,
    ApprovalSignatureProofKind, ApprovalTarget, CapabilityActionId, Event,
    EventAdmissionSubmission, EventKind, Hash, ManagementOperation, RealmId, ScopeRef,
    ServiceOperationId,
};

use super::*;
use crate::harness::{ArkretServer, expect_json};
use crate::scenarios::mls_lifecycle_live::{Member, accepted_full_view};

mod effects;
mod service;
use service::ManagedService;

const SCOPE: [&str; 10] = [
    "ak.self.applet.ghost.command.preview.v1",
    "ak.self.applet.bot.command.preview.v1",
    "ak.edge.applet.managed_actor.command.author.v1",
    "ak.self.applet.configuration.command.submit.v1",
    "ak.peer.applet.configuration.command.submit.v1",
    "ak.edge.applet.configuration.command.execute.v1",
    "ak.edge.applet.command.transaction.v1",
    "ak.self.management_review.command.request.v1",
    "ak.self.management_review.command.decide.v1",
    "ak.self.management_review.read.status.v1",
];

fn op(name: &str) -> Result<ServiceOperationId> {
    ServiceOperationId::from_wire(name)
        .with_context(|| format!("unregistered native operation: {name}"))
}

fn vote(
    member: &Member,
    request: &ManagementReviewRequestBody,
    event: &Event,
) -> Result<ApprovalSignature> {
    let principal = member
        .client
        .principal
        .as_ref()
        .context("accepted native approver absent")?;
    let mut signature = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: ApprovalContext::Management {
                request_id: request.request_id.clone(),
                management_operation: request.management_operation,
                effective_scope: request.effective_scope.clone(),
            },
            approval_target: ApprovalTarget::Event {
                event_id: event.event_id.clone(),
            },
            request_canonical_digest: Hash::new(arkret_canonical::canonical_sha256(event)?)?,
            operation: ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1.into(),
            action: CapabilityActionId::AppletGhostProvision,
            realm_id: event.realm_id.clone(),
            initiating_actor_id: event.actual_signer().clone(),
            approver_did: principal.did.clone(),
            approved_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            nonce: format!(
                "{}{}",
                uuid::Uuid::now_v7().simple(),
                uuid::Uuid::now_v7().simple()
            ),
        },
        proof: ApprovalSignatureProof {
            kind: ApprovalSignatureProofKind::DetachedJws,
            verification_method: member.method.clone(),
            jws: String::new(),
        },
    };
    signature.proof.jws = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
        member.key.to_bytes(),
        member.method.as_str(),
    )
    .sign_detached_jws(
        &arkret_signatures::approval_signature::approval_signature_signing_bytes(&signature)?,
    );
    arkret_signatures::approval_signature::verify_event_approval_signature_with_verified_controller(
        &signature, event, ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
        CapabilityActionId::AppletGhostProvision, chrono::Utc::now(),
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes:member.key.verifying_key().to_bytes().to_vec() },
        Some(&principal.core_id),
    )?;
    Ok(signature)
}

fn verify_preview(
    service: &ManagedService,
    preview: &AppletManagedActorAuthoringRequest,
    install: &AppletInstallResponseBody,
    expected_scope: &ScopeRef,
    registration: &Event,
    grant: &Event,
) -> Result<()> {
    preview.validate_bindings()?;
    let (applet, scope, registration_ref, authorization_ref, epoch, digest) = match &preview.basis {
        AppletManagedActorAuthoringBasis::ProvisionBot(basis) => (
            &basis.applet_id,
            &basis.effective_scope,
            &basis.registration_event_ref,
            &basis.authorization_ref,
            &basis.registration_epoch_evidence,
            &basis.package_digest,
        ),
        AppletManagedActorAuthoringBasis::ProvisionGhost(basis) => (
            &basis.applet_id,
            &basis.effective_scope,
            &basis.registration_event_ref,
            &basis.authorization_ref,
            &basis.registration_epoch_evidence,
            &basis.package_digest,
        ),
    };
    ensure!(
        applet == &install.applet_id
            && scope == expected_scope
            && registration_ref == &registration.event_id
            && authorization_ref == &arkret_wire::GrantId::from_event_id(&grant.event_id)
            && epoch == &service.epoch
            && Some(digest) == service.package.package_digest.as_ref()
            && preview.basis.service_id() == &service.package.service_id
            && preview.governance_station_id == service.governor_resolution.service_id,
        "preview substituted another installation, epoch, original grant or governor"
    );
    let key = effects::resolution_key(
        &service.governor_resolution,
        &preview.proof.verification_method,
        preview.proof.created_at,
    )?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &preview.proof.jws,
        &preview.proof_binding_bytes()?,
        &key,
    )?;
    Ok(())
}

async fn source_event(
    service: &ManagedService,
    governor: &ArkretServer,
    preview: &AppletManagedActorAuthoringRequest,
) -> Result<Event> {
    let body = AppletManagedActorAuthorRequestBody {
        authoring_request: preview.clone(),
    };
    let response: AppletManagedActorAuthorResponseBody = serde_json::from_value(
        expect_json(
            service.governor_request(
                governor,
                "/_arkret/edge/applet/managed-actors/author",
                op(SCOPE[2])?,
                &body,
                None,
            )?,
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    let event = response.create_event;
    effects::verify_creation(service, &event)?;
    Ok(event)
}

async fn submit_creation(
    service: &ManagedService,
    governor: &ArkretServer,
    event: &Event,
    votes: &[ApprovalSignature],
    key: &str,
) -> Result<(u16, Value)> {
    let submission = SelfAuthoritySubmitRequestBody::Event(EventAdmissionSubmission {
        event: event.clone(),
        approval_signatures: (!votes.is_empty()).then(|| votes.to_vec()),
    });
    let response = service
        .service_request(
            governor,
            "/_arkret/self/events",
            op(ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1)?,
            &submission,
            Some(key),
        )?
        .send()
        .await?;
    let status = response.status().as_u16();
    Ok((status, response.json().await?))
}

async fn configure(
    member: &Member,
    service: &ManagedService,
    body: &AppletConfigurationRequestBody,
) -> Result<Value> {
    expect_json(
        member
            .client
            .post(&format!(
                "/_arkret/self/applets/{}/configuration",
                service.package.applet_id
            ))
            .header("idempotency-key", body.intent.request_id.as_str())
            .json(body),
        reqwest::StatusCode::OK,
    )
    .await
}

async fn scenario() -> Result<(Value, NativeOperationObservations)> {
    let mut governor = crate::harness::heap_future(|| {
        crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment(
            "native-managed-governor",
        )
    })
    .await?;
    let mut account_station = crate::harness::heap_future(|| {
        crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment(
            "native-managed-account",
        )
    })
    .await?;
    ensure!(
        governor.station.service_id() != account_station.station.service_id()
            && governor.station.owned_database_url()
                != account_station.station.owned_database_url(),
        "management requires independent Account and Realm authorities/storage"
    );
    let relay = governor.station.install_service_route_relay().await?;
    governor
        .station
        .restart_with_federation_mesh(&[account_station.station.url("")])
        .await?;
    account_station
        .station
        .restart_with_federation_mesh(&[governor.station.url("")])
        .await?;
    let owner =
        super::mls_interop::member(governor.controller.clone(), governor.station.service_id())?;
    let administrator = super::mls_interop::member(
        account_station.controller.clone(),
        account_station.station.service_id(),
    )?;
    let realm: RealmId = crate::scenarios::human_device_producer_live::create_realm_with_join_rule(
        &owner.client,
        "Native managed Applet",
        "public",
        &[&governor.station, &account_station.station],
    )
    .await?
    .parse()?;
    crate::scenarios::human_device_producer_live::prepare_join(
        &administrator.client,
        realm.as_str(),
        &governor.station,
        &arkret_identifiers::new_prefixed_uuid7("ak:request:"),
        arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent::MemberJoin,
    )
    .await?;
    let join=administrator.client.author_event(realm.as_str(),EventKind::MemberState.as_str(),crate::scenarios::human_device_producer_live::membership_payload(realm.as_str(),administrator.account.clone(),arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join,"native configuration administrator")?).await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &administrator.client,
        &administrator.account,
        administrator.device.as_str(),
        &join,
    )
    .await?;
    let mut permissions = Vec::new();
    for member in [&owner, &administrator] {
        let grant = crate::scenarios::human_device_producer_live::grant_realm_actions(
            &owner.client,
            &governor.station,
            realm.as_str(),
            &member.account,
            &[
                CapabilityActionId::REALM_ADMIN,
                CapabilityActionId::MESSAGE_CREATE,
            ],
        )
        .await?;
        permissions.push(accepted_full_view(&owner.client, &grant.event_ref).await?);
    }
    let mut service = ManagedService::start(&governor.station).await?;
    let (installed, registration_event, grant_event) =
        service.install(&governor.station, &owner, &realm).await?;
    let registration = accepted_full_view(&owner.client, &registration_event.event_id).await?;
    let grant = accepted_full_view(&owner.client, &grant_event.event_id).await?;
    ensure!(
        registration.event == registration_event && grant.event == grant_event,
        "installation rewrote producer originals"
    );
    // This scenario requested a Realm installation. Bind that exact request
    // scope to its accepted grant, rather than inventing a response mirror.
    let effective_scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let original_grant: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(serde_json::to_value(&grant.event.payload)?)?;
    ensure!(
        installed.applet_id == service.package.applet_id
            && installed.registration_event_ref == registration.event.event_id
            && installed.registration_epoch
                == service.package.compute_registration_epoch(&service.epoch)?
            && installed
                .capability_grant_refs
                .contains(&arkret_wire::GrantId::from_event_id(&grant.event.event_id))
            && matches!(
                &original_grant.grant.subject,
                arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(
                    ActorId::Service { service_id }
                ) if service_id == &installed.service_id
            )
            && original_grant
                .grant
                .resources
                .iter()
                .any(|resource| resource.is_exact_scope(&effective_scope)),
        "accepted registration/grant does not bind this exact requested installation"
    );
    let before_previews =
        effects::snapshot(&governor.station, &realm, &installed.applet_id).await?;
    let ghost_request = GhostPreviewRequestBody {
        effective_scope: effective_scope.clone(),
        external_ref: GhostExternalTuple {
            protocol: "fixture".into(),
            instance_id: "native-instance".into(),
            external_id: format!("native-ghost-{}", uuid::Uuid::now_v7().simple()),
        },
        display_name: Some("Native original Ghost".into()),
    };
    let ghost: GhostPreviewResponseBody = serde_json::from_value(
        expect_json(
            service.service_request(
                &governor.station,
                &format!(
                    "/_arkret/self/applets/{}/ghosts/provision/preview",
                    installed.applet_id
                ),
                op(SCOPE[0])?,
                &ghost_request,
                None,
            )?,
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        ghost.existing_managed_actor.is_none(),
        "fresh Ghost was already mapped"
    );
    let bot_request = AppletBotPreviewRequestBody {
        service_id: service.package.service_id.clone(),
        effective_scope: effective_scope.clone(),
        request_id: uuid::Uuid::now_v7().simple().to_string(),
        display_name: Some("Preview only Bot".into()),
    };
    let bot: AppletBotPreviewResponseBody = serde_json::from_value(
        expect_json(
            service.service_request(
                &governor.station,
                &format!(
                    "/_arkret/self/applets/{}/bots/provision/preview",
                    installed.applet_id
                ),
                op(SCOPE[1])?,
                &bot_request,
                None,
            )?,
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    verify_preview(
        &service,
        &ghost.authoring_request,
        &installed,
        &effective_scope,
        &registration_event,
        &grant_event,
    )?;
    verify_preview(
        &service,
        &bot.authoring_request,
        &installed,
        &effective_scope,
        &registration_event,
        &grant_event,
    )?;
    let ghost_event = source_event(&service, &governor.station, &ghost.authoring_request).await?;
    let ghost_replay = source_event(&service, &governor.station, &ghost.authoring_request).await?;
    let after_previews = effects::snapshot(&governor.station, &realm, &installed.applet_id).await?;
    ensure!(
        ghost_replay == ghost_event && before_previews == after_previews,
        "preview/author accepted business history or changed the frozen Service Event"
    );

    let policy_id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let target = AppletPolicyTarget::Installation {
        applet_id: installed.applet_id.clone(),
        service_id: installed.service_id.clone(),
        effective_scope: effective_scope.clone(),
    };
    let policy=owner.client.author_event(realm.as_str(),EventKind::PolicySet.as_str(),json!({
        "policy_id":policy_id,"expected_commit_id":null,"value":{"schema":"ak.schema.policy.v1","id":policy_id,"realm_id":realm,"policy_kind":"applet","default_effect":"allow","created_by":owner.actor,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        "rules":[{"rule_id":"native_map_ghost_review","kind":"applet","effect":"require_review","applet_target":target,"applet_operations":["map_ghost"],"review_requirement":{"approver_actor_ids":[owner.actor],"min_approver_count":1,"max_age_seconds":3600}}]}})).await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &owner.client,
        &owner.account,
        owner.device.as_str(),
        &policy,
    )
    .await?;
    let policy = accepted_full_view(&owner.client, &policy.event_id).await?;
    let before_pending = effects::snapshot(&governor.station, &realm, &installed.applet_id).await?;
    let rejected = submit_creation(
        &service,
        &governor.station,
        &ghost_event,
        &[],
        &uuid::Uuid::now_v7().to_string(),
    )
    .await?;
    ensure!(
        rejected.0 == 403,
        "current require_review admitted an unapproved candidate: {rejected:?}"
    );
    ensure!(
        effects::snapshot(&governor.station, &realm, &installed.applet_id).await? == before_pending,
        "unapproved candidate wrote business effects"
    );
    let review = ManagementReviewRequestBody {
        request_id: format!("native-review-{}", uuid::Uuid::now_v7()),
        effective_scope: effective_scope.clone(),
        management_operation: ManagementOperation::MapGhost,
        requester_actor_id: ActorId::service(installed.service_id.clone()),
        target: ManagementReviewTarget::Event {
            event: Box::new(ghost_event.clone()),
        },
        configuration_ref: None,
    };
    review.validate()?;
    let pending: ManagementReviewResponseBody = serde_json::from_value(
        expect_json(
            service.service_request(
                &governor.station,
                "/_arkret/self/management-reviews/requests",
                op(SCOPE[7])?,
                &review,
                Some(&review.request_id),
            )?,
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        pending.status == ManagementReviewStatus::Pending
            && pending.target_digest == review.target.canonical_target_digest()?,
        "review lost its exact unaccepted target"
    );
    let pending_rows = effects::snapshot(&governor.station, &realm, &installed.applet_id).await?;
    effects::same_canonical(&before_pending, &pending_rows)?;
    let lookup = ManagementReviewLookupRequestBody {
        request_id: review.request_id.clone(),
    };
    let pending_status: ManagementReviewResponseBody = serde_json::from_value(
        expect_json(
            service.service_request(
                &governor.station,
                "/_arkret/self/management-reviews/status",
                op(SCOPE[9])?,
                &lookup,
                None,
            )?,
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        pending_status.status == ManagementReviewStatus::Pending
            && pending_status.target_digest == pending.target_digest,
        "status changed the target or exposed approval"
    );
    let approval = vote(&owner, &review, &ghost_event)?;
    let decision = ManagementReviewDecisionRequestBody {
        request_id: review.request_id.clone(),
        expected_status: ManagementReviewStatus::Pending,
        decision: ManagementReviewDecision::Approve,
        approval_signatures: vec![approval.clone()],
    };
    let approved: ManagementReviewResponseBody = serde_json::from_value(
        expect_json(
            owner
                .client
                .post("/_arkret/self/management-reviews/decisions")
                .header("idempotency-key", &review.request_id)
                .json(&decision),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        approved.status == ManagementReviewStatus::Approved
            && approved.target_digest == pending.target_digest
            && approved.approval_signatures == vec![approval.clone()],
        "decision substituted its exact vote or target"
    );
    let approved_rows = effects::snapshot(&governor.station, &realm, &installed.applet_id).await?;
    effects::same_canonical(&pending_rows, &approved_rows)?;
    let admission_key = uuid::Uuid::now_v7().to_string();
    let admitted = submit_creation(
        &service,
        &governor.station,
        &ghost_event,
        std::slice::from_ref(&approval),
        &admission_key,
    )
    .await?;
    ensure!(
        admitted.0 == 200,
        "approved native creation refused: {admitted:?}"
    );
    let ghost_committed = accepted_full_view(&owner.client, &ghost_event.event_id).await?;
    ensure!(
        ghost_committed.event == ghost_event,
        "governor replaced the Service creation Event"
    );
    let consumed: ManagementReviewResponseBody = serde_json::from_value(
        expect_json(
            service.service_request(
                &governor.station,
                "/_arkret/self/management-reviews/status",
                op(SCOPE[9])?,
                &lookup,
                None,
            )?,
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        consumed.status == ManagementReviewStatus::Consumed
            && consumed.target_digest == pending.target_digest,
        "accepted target did not consume its review"
    );

    let mut configuration = AppletConfigurationRequestBody {
        command: AppletConfigurationCommand::Recover,
        intent: AppletConfigurationIntent {
            request_id: arkret_identifiers::new_prefixed_uuid7("ak:request:").parse()?,
            service_id: installed.service_id.clone(),
            effective_scope: effective_scope.clone(),
            selection: AppletConfigurationSelection::NewBot {
                display_name: Some("Native configured Bot".into()),
            },
        },
        approval_signatures: None,
    };
    let not_started = configure(&administrator, &service, &configuration).await?;
    ensure!(
        serde_json::from_value::<AppletConfigurationResponseBody>(not_started.clone())?
            .admission_status
            == AppletConfigurationAdmissionStatus::NotStarted,
        "Recover manufactured a prior configuration"
    );
    configuration.command = AppletConfigurationCommand::Configure;
    let configured = configure(&administrator, &service, &configuration).await?;
    let outcome: AppletConfigurationResponseBody = serde_json::from_value(configured.clone())?;
    ensure!(
        outcome.admission_status == AppletConfigurationAdmissionStatus::Accepted
            && outcome.request_id == configuration.intent.request_id,
        "native A-to-G-to-S configuration was not accepted"
    );
    let source = outcome
        .source_response_body
        .as_ref()
        .context("actual source response absent")?;
    let bot_event = source
        .create_event
        .as_deref()
        .context("original configuration creation absent")?
        .clone();
    effects::verify_creation(&service, &bot_event)?;
    let bot_committed = accepted_full_view(&owner.client, &bot_event.event_id).await?;
    ensure!(
        bot_committed.event == bot_event,
        "configuration substituted the source Event"
    );
    let completed = effects::wait_delivered(
        &governor.station,
        &realm,
        &installed.applet_id,
        &[&ghost_committed, &bot_committed],
    )
    .await?;
    let replay = configure(&administrator, &service, &configuration).await?;
    ensure!(
        replay == configured,
        "exact configuration replay changed the retained source outcome"
    );
    configuration.command = AppletConfigurationCommand::Recover;
    let recover = configure(&administrator, &service, &configuration).await?;
    ensure!(
        recover == configured,
        "Recover changed the exact accepted original outcome"
    );
    let accepted_replay = submit_creation(
        &service,
        &governor.station,
        &ghost_event,
        std::slice::from_ref(&approval),
        &admission_key,
    )
    .await?;
    ensure!(
        accepted_replay == admitted,
        "exact creation replay changed its accepted result"
    );
    let before_conflict =
        effects::snapshot(&governor.station, &realm, &installed.applet_id).await?;
    let mut changed = configuration.clone();
    changed.command = AppletConfigurationCommand::Configure;
    changed.intent.selection = AppletConfigurationSelection::NewBot {
        display_name: Some("A different immutable intent".into()),
    };
    let response = administrator
        .client
        .post(&format!(
            "/_arkret/self/applets/{}/configuration",
            installed.applet_id
        ))
        .header("idempotency-key", changed.intent.request_id.as_str())
        .json(&changed)
        .send()
        .await?;
    let conflict_status = response.status().as_u16();
    let conflict: Value = response.json().await?;
    ensure!(
        conflict_status == 409,
        "same RequestId accepted another intent: {conflict_status} {conflict}"
    );
    let after_conflict = effects::snapshot(&governor.station, &realm, &installed.applet_id).await?;
    ensure!(
        before_conflict == after_conflict,
        "replay/conflict changed canonical/current/quota/installation effects"
    );
    effects::same_canonical(&completed, &after_conflict)?;
    let mut additional = NativeOperationObservations::default();
    for observed in service.host.observations()? {
        additional.exchanges.extend(observed.exchanges);
    }
    additional
        .exchanges
        .extend(relay.operation_observations().exchanges);
    let source_value = serde_json::to_value(source)?;
    let source_execution: AppletConfigurationExecutionRequestBody = serde_json::from_value(
        additional
            .exchanges
            .iter()
            .find(|row| {
                row.operation_id.as_str() == SCOPE[5]
                    && row.request_body["command"] == "configure"
                    && row.response_body == source_value
            })
            .context("actual G-to-S execution source exchange absent")?
            .request_body
            .clone(),
    )?;
    source.validate_for(&source_execution.intent)?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &source.proof.jws,
        &source.signature_payload()?,
        &effects::resolution_key(
            &service.identity.resolution,
            &source.proof.verification_method,
            source.evaluated_at,
        )?,
    )?;
    let cold = service.cold_restart(&governor.station).await?;
    effects::require_cold_originals(&cold, &[&ghost_committed, &bot_committed])?;
    let (cold_source_request, cold_source_response) = service
        .replay_source(&governor.station, &source_execution)
        .await?;
    ensure!(
        serde_json::to_value(&cold_source_response)? == source_value,
        "cold S did not retain the exact signed source response"
    );
    let cold_recover = configure(&administrator, &service, &configuration).await?;
    ensure!(
        cold_recover == configured,
        "cold recovery changed source bytes, proof, timestamp or accepted references"
    );
    ensure!(
        effects::snapshot(&governor.station, &realm, &installed.applet_id).await? == after_conflict,
        "cold recovery wrote duplicate business effects"
    );
    let source_process = service.host.identity()?;
    for observed in service.host.observations()? {
        additional.exchanges.extend(observed.exchanges);
    }
    let originals = vec![
        registration.clone(),
        grant.clone(),
        policy.clone(),
        ghost_committed.clone(),
        bot_committed.clone(),
    ];
    let artifact = json!({"realm_id":realm,"governor":governor.station.service_id(),"account_station":account_station.station.service_id(),"administrator":administrator.actor,"approver":owner.actor,"approver_method":owner.method,"approver_public_key_base64url":arkret_canonical::base64url_encode(owner.key.verifying_key().to_bytes()),
        "package":service.package,"service_resolution":service.identity.resolution,"governor_resolution":service.governor_resolution,"installed":installed,"registration":registration,"grant":grant,"permissions":permissions,"originals":originals,
        "ghost_preview_request":ghost_request,"ghost_preview":ghost,"bot_preview_request":bot_request,"bot_preview":bot,"ghost_event":ghost_event,"ghost_author_replay":ghost_replay,"review_request":review,"pending":pending,"pending_status":pending_status,"decision":decision,"approved":approved,"consumed":consumed,"unapproved":{ "status":rejected.0,"problem":rejected.1 },"admitted":admitted.1,"admission_replay":accepted_replay.1,"ghost_committed":ghost_committed,
        "configuration_request":configuration,"source_execution":source_execution,"not_started":not_started,"configured":configured,"replay":replay,"recover":recover,"bot_committed":bot_committed,"conflict":{"status":conflict_status,"problem":conflict},"cold":cold,"cold_recover":cold_recover,"cold_source_request":cold_source_request,"cold_source_response":cold_source_response,
        "snapshots":{"before_previews":before_previews,"after_previews":after_previews,"before_pending":before_pending,"pending":pending_rows,"approved":approved_rows,"completed":completed,"before_conflict":before_conflict,"after_conflict":after_conflict},
        "processes":[governor.coauth.server.native_process_identity()?,governor.station.native_process_identity()?,account_station.coauth.server.native_process_identity()?,account_station.station.native_process_identity()?,source_process]});
    Ok((artifact, additional))
}

pub(super) async fn run() -> Result<()> {
    let (result, mut observations) = observe(crate::harness::heap_future(scenario)).await;
    let (mut artifact, additional) = match result {
        Ok(value) => value,
        Err(error) => {
            retain_attempt("applet-managed-configuration", &observations)?;
            return Err(error);
        }
    };
    observations.exchanges.extend(additional.exchanges);
    retain_attempt("applet-managed-configuration", &observations)?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    verify_native_issuer_bindings(&observations)?;
    let resolution = serde_json::from_value(artifact["governor_resolution"].clone())?;
    for original in artifact["originals"]
        .as_array()
        .context("native creation originals absent")?
    {
        effects::verify_commit(&resolution, &serde_json::from_value(original.clone())?)?;
    }
    artifact["case"] = json!("applet_managed_configuration");
    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("applet-managed-configuration.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
