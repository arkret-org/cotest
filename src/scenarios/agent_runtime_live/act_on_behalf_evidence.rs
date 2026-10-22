//! Real attributed execution under a narrow key, grant and private confirmation.

use super::*;
use crate::harness::CanonicalJsonBody;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

pub async fn run_agent_act_on_behalf_boundary() -> Result<()> {
    use arkret_models_collaboration::events_payloads::agent::AgentActionRequestPayload;
    use arkret_models_collaboration::events_payloads::message::MessageCreatePayload;
    let deployment =
        coauth_session_evidence::actual_agent_deployment("agent-act-on-behalf").await?;
    let station = &deployment.station;
    let controller = &deployment.controller;
    let created = controller
        .create_realm_with(json!({
            "title":"Attributed Agent execution", "public":false, "join_rule":"public",
            "plaintext_visible_services":[station.service_id()]
        }))
        .await?;
    let realm = RealmId::new(created["realm_id"].as_str().context("created Realm")?)?;
    let strand = arkret_wire::StrandId::new(
        created["default_strand_id"]
            .as_str()
            .context("default Strand")?,
    )?;
    let generation = EventId::new(
        created["event_response"]["commits"]
            .as_array()
            .and_then(|commits| commits.last())
            .and_then(|commit| commit["event_ref"].as_str())
            .context("controller membership generation")?,
    )?;
    let mut operations = runtime_operations().to_vec();
    operations.push(ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1);
    operations.push("ak.message.create");
    operations.push("ak.reaction.add");
    let completed_operations =
        arkret_schema::agent_runtime_scope::complete_agent_runtime_scope(operations)?;
    let operations = completed_operations
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let mut scope = requested_scope(&operations)?;
    scope.resources.push(serde_json::from_value(json!({
        "kind":"strand", "realm_id":realm, "resource_ref":strand
    }))?);
    let issuer = AgentSessionIssuer::Coauth {
        base: deployment.coauth.base_url(),
        database_url: &deployment.coauth.pg.connect_url,
    };
    let agent = AgentRuntimeSession::establish_paired_observed(
        station,
        &issuer,
        controller,
        &deployment.account,
        "attributed-agent",
        scope,
        None,
    )
    .await?;
    let mut joined = MembershipPayload::join(
        realm.clone(),
        ActorId::account(agent.agent_account.clone()),
        "controller joins the exact attributed Agent",
    );
    joined.agent_controller_binding = Some(AgentControllerMembershipBinding {
        controller_account_id: deployment.account.clone(),
        controller_membership_generation_ref: generation,
        controller_terminal_event_ref: None,
    });
    controller
        .submit_event(realm.as_str(), "ak.member.state", joined.to_value()?)
        .await?;
    let mode = arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload {
        agent_account_id: agent.agent_account.clone(),
        controller_account_id: deployment.account.clone(),
        interaction_mode:
            arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public,
        expected_revision: None,
    };
    controller
        .submit_event(
            realm.as_str(),
            "ak.agent.interaction.set",
            serde_json::to_value(mode)?,
        )
        .await?;
    let selection = arkret::ParticipationReplaceRequestBody {
        target_scope: arkret::ParticipationScope::Realm {
            realm_id: realm.clone(),
        },
        selection: arkret::ParticipationBits {
            act_on_behalf: true,
            reaction_add: true,
            ..arkret::ParticipationBits::NONE
        },
        expected_version: 0,
    };
    let selected = controller
        .sdk()
        .agent_participation_replace(agent.agent_account.principal_id.as_str(), &selection)
        .await?;
    ensure!(
        selected
            .agent_participation_entries
            .iter()
            .any(|entry| entry.scope == selection.target_scope
                && entry.selection == selection.selection
                && entry.version == 1)
    );
    let body = arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody {
        schema: SchemaId::CAPABILITY_V1.to_owned(),
        realm_id: Some(realm.clone()),
        issuer_id: ActorId::account(deployment.account.clone()),
        subject:
            arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(
                ActorId::account(agent.agent_account.clone()),
            ),
        actions: vec!["ak.message.create".to_owned()],
        resources: vec![arkret_wire::WireResourceSelector::strand(
            realm.clone(),
            strand.clone(),
        )],
        constraints: vec![serde_json::from_value(json!({
            "constraint_kind":"scope_limitation", "effect":"allow",
            "allowed_strand_ids":[strand], "allowed_tracks":["discussion"]
        }))?],
        issuer_authority_refs: vec![arkret::IssuerAuthorityRef::RealmRoot {
            realm_id: realm.clone(),
            authority_event_ref: realm.event_id(),
            authority_generation: 0,
        }],
        issued_at: Utc::now(),
    };
    let grant = controller
        .author_event(
            realm.as_str(),
            "ak.capability.grant",
            serde_json::to_value(
                arkret_models_collaboration::events_payloads::CapabilityGrantPayload {
                    grant: body.clone(),
                },
            )?,
        )
        .await?;
    let grant_ref = grant.event_id.clone();
    let grant_id = arkret_wire::GrantId::from_event_id(&grant_ref);
    let outcome: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/self/events")
                .canonical_json(&arkret_wire::EventAdmissionSubmission::new(grant))?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(matches!(
        outcome,
        AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            ..
        }
    ));
    let mut reaction_body = body;
    reaction_body.actions = vec!["ak.reaction.add".to_owned()];
    let reaction_grant = controller
        .author_event(
            realm.as_str(),
            "ak.capability.grant",
            serde_json::to_value(
                arkret_models_collaboration::events_payloads::CapabilityGrantPayload {
                    grant: reaction_body,
                },
            )?,
        )
        .await?;
    let wrong_action_grant = arkret_wire::GrantId::from_event_id(&reaction_grant.event_id);
    expect_json(
        controller
            .post("/_arkret/self/events")
            .canonical_json(&arkret_wire::EventAdmissionSubmission::new(reaction_grant))?,
        StatusCode::OK,
    )
    .await?;
    let (credential, issued_request) = coauth_session_evidence::issue_runtime_session_with_scope(
        station,
        deployment.coauth.base_url(),
        &deployment.coauth.pg.connect_url,
        &agent.agent_account.principal_id,
        &agent.key_authorization,
        &agent.verification_method,
        &agent.runtime_key,
        &operations,
        arkret_models_collaboration::session_grants::SessionGrantAgentScopeRequest {
            realm_ids: Vec::new(),
            strand_ids: vec![strand.clone()],
            track_names: vec![NonEmptyString::new("discussion").map_err(anyhow::Error::msg)?],
        },
    )
    .await
    .context("real issuer grants the exact attributed content scope")?;
    let runtime = station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "attributed-runtime",
        credential.clone(),
        agent.runtime_key.clone(),
    )?;
    let message: MessageCreatePayload = serde_json::from_value(json!({
        "strand_id":strand, "track_name":"discussion", "content":{"kind":"ak.content.text","body":"Controller approved attribution"}
    }))?;
    let target = sign(
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MessageCreate>::new(
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            ActorId::account(deployment.account.clone()),
            message,
        )?
        .with_executed_by(ActorId::account(agent.agent_account.clone()))
        .with_authorization_ref(
            arkret_wire::AuthorizationRef::new(grant_id.as_str()).map_err(anyhow::Error::msg)?,
        )
        .author_with_digest_suite(Utc::now(), arkret_canonical::DigestSuite::Sha256)?,
        &agent.verification_method,
        agent.runtime_key.to_bytes(),
    )?;
    let database = station
        .owned_database_url()
        .context("actual Station database")?;
    let unselected_before = acceptance_rows_with_agent_stores(database, true).await?;
    let unselected = runtime
        .post("/_arkret/self/events")
        .canonical_json(&arkret_wire::EventAdmissionSubmission::new(target.clone()))?
        .send()
        .await?;
    let unselected_status = unselected.status();
    let unselected_body = unselected.bytes().await?;
    let unselected_problem: arkret_wire::Problem = serde_json::from_slice(&unselected_body)
        .with_context(|| {
            format!(
                "unselected attributed publication accepted or malformed: {unselected_status} {}",
                String::from_utf8_lossy(&unselected_body)
            )
        })?;
    ensure!(
        unselected_status == StatusCode::FORBIDDEN
            && unselected_problem.code() == arkret_wire::ErrorCode::CLAIM_REQUIRED
            && serde_json::to_value(&unselected_problem)?["reason_code"] == "approval_required",
        "unselected attributed publication without fresh approval: {unselected_status} {unselected_problem:?}"
    );
    ensure!(unselected_before == acceptance_rows_with_agent_stores(database, true).await?);
    let requested_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let request: AgentActionRequestPayload = serde_json::from_value(json!({
        "request_id":unique_uuid7(), "agent_id":agent.agent_account.principal_id,
        "controller_account_id":deployment.account, "proposed_action":"ak.message.create",
        "target":{"kind":"strand","realm_id":realm,"object_ref":strand},
        "request_canonical_digest":arkret_canonical::canonical_sha256(&target)?,
        "expires_at":arkret_canonical::format_timestamp_canonical(requested_at+chrono::Duration::minutes(5)),
        "created_at":arkret_canonical::format_timestamp_canonical(requested_at),
    }))?;
    let selected_request = request.clone();
    let private_created_at = request.created_at;
    let private = sign(
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::AgentActionRequest>::new(
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            ActorId::account(agent.agent_account.clone()),
            request,
        )?
        .author_with_digest_suite(private_created_at, arkret_canonical::DigestSuite::Sha256)?,
        &agent.verification_method,
        agent.runtime_key.to_bytes(),
    )?;
    let response = submit_actor_private(&runtime, &private).await?;
    ensure!(
        response.status().is_success(),
        "actual private request rejected: {} {}",
        response.status(),
        response.text().await?
    );
    let before = acceptance_rows_with_agent_stores(database, true).await?;
    let mismatched = controller
        .post("/_arkret/self/events")
        .canonical_json(&arkret_wire::EventAdmissionSubmission::new(target.clone()))?
        .send()
        .await?;
    let status = mismatched.status();
    let problem: arkret_wire::Problem = mismatched.json().await?;
    ensure!(
        status == StatusCode::FORBIDDEN
            && problem.code() == arkret_wire::ErrorCode::CAPABILITY_DENIED,
        "controller session borrowed the independent Agent producer: {status} {problem:?}"
    );
    ensure!(before == acceptance_rows_with_agent_stores(database, true).await?);
    let response = runtime
        .post("/_arkret/self/events")
        .canonical_json(&arkret_wire::EventAdmissionSubmission::new(target.clone()))?
        .send()
        .await?;
    let status = response.status();
    let refused: arkret_wire::Problem = response.json().await?;
    ensure!(
        status == StatusCode::FORBIDDEN
            && refused.code() == arkret_wire::ErrorCode::CLAIM_REQUIRED
            && serde_json::to_value(&refused)?["reason_code"] == "approval_required",
        "selected attributed publication without confirmation: {status} {refused:?}"
    );
    ensure!(before == acceptance_rows_with_agent_stores(database, true).await?);
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow::anyhow!("approval nonce generation failed: {error}"))?;
    let approval = arkret_models_collaboration::events_payloads::agent::AgentActionApprovePayload {
        approval_id: unique_uuid7(),
        request_id: Some(selected_request.request_id.clone()),
        draft_id: None,
        agent_id: agent.agent_account.principal_id.clone(),
        proposed_action: selected_request.proposed_action.clone(),
        target: selected_request.target.clone(),
        approved_event_id: target.event_id.clone(),
        draft_content_digest: None,
        approval_nonce: URL_SAFE_NO_PAD.encode(nonce),
        expires_at: arkret_canonical::normalize_timestamp_canonical(Utc::now())
            + chrono::Duration::minutes(2),
    };
    let approved = controller
        .author_event(
            realm.as_str(),
            "ak.agent.action_approve",
            serde_json::to_value(&approval)?,
        )
        .await?;
    let approved_outcome: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            controller.post("/_arkret/self/events").canonical_json(
                &arkret_wire::EventAdmissionSubmission::new(approved.clone()),
            )?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(matches!(
        approved_outcome,
        AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            ..
        }
    ));
    let after_confirmation = acceptance_rows_with_agent_stores(database, true).await?;
    let retried_confirmation: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            controller.post("/_arkret/self/events").canonical_json(
                &arkret_wire::EventAdmissionSubmission::new(approved.clone()),
            )?,
            StatusCode::OK,
        )
        .await?,
    )?;
    let (
        AuthoritySubmitOutcome::Accepted {
            commit: original_confirmation,
            ..
        },
        AuthoritySubmitOutcome::Accepted {
            commit: confirmation_retry,
            ..
        },
    ) = (&approved_outcome, &retried_confirmation)
    else {
        anyhow::bail!("confirmation retry lost its accepted Commit");
    };
    ensure!(original_confirmation == confirmation_retry);
    ensure!(after_confirmation == acceptance_rows_with_agent_stores(database, true).await?);
    let mut rebound = approval.clone();
    rebound.approval_id = unique_uuid7();
    let rebound_event = controller
        .author_event(
            realm.as_str(),
            "ak.agent.action_approve",
            serde_json::to_value(rebound)?,
        )
        .await?;
    let refused = controller
        .post("/_arkret/self/events")
        .canonical_json(&arkret_wire::EventAdmissionSubmission::new(rebound_event))?
        .send()
        .await?;
    let status = refused.status();
    let problem: arkret_wire::Problem = refused.json().await?;
    ensure!(
        status == StatusCode::CONFLICT
            && serde_json::to_value(&problem)?["reason_code"] == "approval_nonce_reused",
        "nonce rebinding returned {status} {problem:?}"
    );
    ensure!(after_confirmation == acceptance_rows_with_agent_stores(database, true).await?);
    let mut foreign_request = approval.clone();
    foreign_request.approval_id = unique_uuid7();
    foreign_request.request_id = Some(unique_uuid7());
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow::anyhow!("approval nonce generation failed: {error}"))?;
    foreign_request.approval_nonce = URL_SAFE_NO_PAD.encode(nonce);
    let foreign_event = controller
        .author_event(
            realm.as_str(),
            "ak.agent.action_approve",
            serde_json::to_value(foreign_request)?,
        )
        .await?;
    let refused = controller
        .post("/_arkret/self/events")
        .canonical_json(&arkret_wire::EventAdmissionSubmission::new(foreign_event))?
        .send()
        .await?;
    let status = refused.status();
    let problem: arkret_wire::Problem = refused.json().await?;
    ensure!(
        status == StatusCode::CONFLICT
            && problem.code() == arkret_wire::ErrorCode::FAILED_PRECONDITION,
        "unknown private request confirmation returned {status} {problem:?}"
    );
    ensure!(after_confirmation == acceptance_rows_with_agent_stores(database, true).await?);
    let submitted = arkret_wire::EventAdmissionSubmission::new(target.clone());
    let response = runtime
        .post("/_arkret/self/events")
        .canonical_json(&submitted)?
        .send()
        .await?;
    let status = response.status();
    let body = response.bytes().await?;
    ensure!(
        status.is_success(),
        "real approved publication rejected: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let published: AuthoritySubmitOutcome = serde_json::from_slice(&body)?;
    let AuthoritySubmitOutcome::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit: original_commit,
    } = published
    else {
        anyhow::bail!("fresh approved publication did not commit: {published:?}");
    };
    ensure!(original_commit.event_ref == target.event_id);
    ensure!(
        controller
            .sdk()
            .committed_event_get(&target.event_id)
            .await?
            .reducer_input()
            == Some(&target)
    );
    let published_rows = acceptance_rows_with_agent_stores(database, true).await?;
    let wrong_holder = controller
        .post("/_arkret/self/events")
        .canonical_json(&submitted)?
        .send()
        .await?;
    let status = wrong_holder.status();
    let problem: arkret_wire::Problem = wrong_holder.json().await?;
    ensure!(
        status == StatusCode::UNAUTHORIZED
            && problem.code() == arkret_wire::ErrorCode::UNAUTHENTICATED,
        "controller borrowed the accepted Agent producer on recovery: {status} {problem:?}"
    );
    ensure!(published_rows == acceptance_rows_with_agent_stores(database, true).await?);
    let response = runtime
        .post("/_arkret/self/events")
        .canonical_json(&submitted)?
        .send()
        .await?;
    let status = response.status();
    let body = response.bytes().await?;
    ensure!(
        status.is_success(),
        "exact approved publication retry failed: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let retried: AuthoritySubmitOutcome = serde_json::from_slice(&body)?;
    let AuthoritySubmitOutcome::Accepted {
        commit: retried_commit,
        ..
    } = retried
    else {
        anyhow::bail!("exact approved publication retry lost its original: {retried:?}");
    };
    ensure!(
        original_commit == retried_commit,
        "exact publication retry changed the covering Commit"
    );
    ensure!(published_rows == acceptance_rows_with_agent_stores(database, true).await?);
    // Each denied publication has its own accepted exact confirmation, so a
    // missing fresh approval cannot conceal the independently tested gate.
    let no_reference = attributed_message(
        &realm,
        &strand,
        &deployment.account,
        &agent,
        None,
        "Missing selected authorization",
    )?;
    confirm_target(
        &deployment,
        &runtime,
        &agent,
        &realm,
        &strand,
        &no_reference,
    )
    .await?;
    refuse_target(
        &runtime,
        database,
        &no_reference,
        &[
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            arkret_wire::ErrorCode::CAPABILITY_DENIED,
        ],
    )
    .await?;
    let wrong_scope = attributed_message(
        &realm,
        &strand,
        &deployment.account,
        &agent,
        Some(&wrong_action_grant),
        "Wrong selected grant action",
    )?;
    confirm_target(&deployment, &runtime, &agent, &realm, &strand, &wrong_scope).await?;
    refuse_target(
        &runtime,
        database,
        &wrong_scope,
        &[arkret_wire::ErrorCode::CAPABILITY_DENIED],
    )
    .await?;
    let participation_target = attributed_message(
        &realm,
        &strand,
        &deployment.account,
        &agent,
        Some(&grant_id),
        "Closed private participation",
    )?;
    confirm_target(
        &deployment,
        &runtime,
        &agent,
        &realm,
        &strand,
        &participation_target,
    )
    .await?;
    let closed = arkret::ParticipationReplaceRequestBody {
        target_scope: selection.target_scope.clone(),
        selection: arkret::ParticipationBits {
            act_on_behalf: false,
            ..selection.selection
        },
        expected_version: 1,
    };
    let changed = controller
        .sdk()
        .agent_participation_replace(agent.agent_account.principal_id.as_str(), &closed)
        .await?;
    ensure!(
        changed
            .agent_participation_entries
            .iter()
            .any(|entry| entry.scope == closed.target_scope
                && entry.version == 2
                && !entry.selection.act_on_behalf)
    );
    let refused = refuse_target(
        &runtime,
        database,
        &participation_target,
        &[arkret_wire::ErrorCode::FAILED_PRECONDITION],
    )
    .await?;
    ensure!(
        refused.detail.contains("agent_act_on_behalf_not_permitted"),
        "another gate concealed private participation: {refused:?}"
    );
    let restored = arkret::ParticipationReplaceRequestBody {
        expected_version: 2,
        ..selection.clone()
    };
    controller
        .sdk()
        .agent_participation_replace(agent.agent_account.principal_id.as_str(), &restored)
        .await?;
    let before_sidecar = acceptance_rows_with_agent_stores(database, true).await?;
    let illegal_sidecar = arkret_models_collaboration::sidecar_operations::SidecarEnsureRequestBody::Prepare(
        arkret_models_collaboration::sidecar_operations::SidecarEnsurePrepareRequestBody {
            phase: arkret_models_collaboration::sidecar_operations::SidecarEnsurePreparePhase::Prepare,
            operation_id: ProtocolOperationId::new(format!("ak:operation:{}", unique_uuid7())).map_err(anyhow::Error::msg)?,
            idempotency_key: IdempotencyKey::new(unique_uuid7()).map_err(anyhow::Error::msg)?,
            source_realm_id: realm.clone(),
            controller_account_id: agent.agent_account.clone(),
            context_ref: arkret_models_collaboration::sidecar_operations::SidecarContextRef::Strand { strand_id: strand.clone() },
        });
    let path = arkret_wire::ServiceOperationId::SelfAgentSidecarCommandEnsureV1
        .descriptor()
        .http_path;
    let refused = controller
        .post(path)
        .canonical_json(&illegal_sidecar)?
        .send()
        .await?;
    let status = refused.status();
    let problem: arkret_wire::Problem = refused.json().await?;
    ensure!(
        status == StatusCode::FORBIDDEN
            && problem.code() == arkret_wire::ErrorCode::CAPABILITY_DENIED
            && serde_json::to_value(&problem)?["reason_code"] == "sidecar_create_denied",
        "foreign-controller Sidecar creation returned {status} {problem:?}"
    );
    ensure!(before_sidecar == acceptance_rows_with_agent_stores(database, true).await?);
    controller
        .revoke_realm_grant(realm.as_str(), wrong_action_grant.as_str())
        .await?;
    controller
        .revoke_realm_grant(realm.as_str(), grant_id.as_str())
        .await?;
    let revoked = acceptance_rows_with_agent_stores(database, true).await?;
    let issue_url = format!(
        "{}/_arkret/gate/account/session-grants",
        deployment.coauth.base_url()
    );
    let mut revoked_intent = issued_request.clone();
    revoked_intent.approval_evidence_refs = Some(vec![grant_ref]);
    coauth_session_evidence::expect_issue_refusal(
        station,
        &deployment.coauth.pg.connect_url,
        &issue_url,
        &coauth_session_evidence::fresh_session_request(
            &revoked_intent,
            &issue_url,
            &agent.runtime_key,
        )?,
        &agent.runtime_key,
        None,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
        None,
    )
    .await
    .context("revoked content source refuses a fresh actual issuance")?;
    ensure!(revoked == acceptance_rows_with_agent_stores(database, true).await?);
    let ledger = coauth_session_evidence::grant_ledger(&deployment.coauth.pg.connect_url).await?;
    let http_proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new("POST", &issue_url),
        &agent.runtime_key,
    )?;
    let response = station
        .http()
        .post(&issue_url)
        .header("DPoP", http_proof.proof_jwt)
        .canonical_json(&issued_request)?
        .send()
        .await?;
    let status = response.status();
    let body = response.bytes().await?;
    ensure!(
        status.is_success(),
        "completed issuance replay after source revocation failed: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let original: arkret_models_collaboration::session_grants::SessionGrantOutcome =
        serde_json::from_slice(&body)?;
    ensure!(
        original.session_grant == credential,
        "completed replay minted a different credential"
    );
    ensure!(
        ledger == coauth_session_evidence::grant_ledger(&deployment.coauth.pg.connect_url).await?
    );
    ensure!(revoked == acceptance_rows_with_agent_stores(database, true).await?);
    println!(
        "[agent-act-on-behalf] real_narrow_content_issuer=1 actual_private_selection=1 unselected_attribution_requires_fresh_approval=1 missing_confirmation_zero_effect_refused=1 actual_controller_confirmation_publication=1 exact_confirmation_retry_original_commit_zero_effect=1 confirmation_nonce_rebinding_zero_effect_refused=1 unknown_confirmation_request_zero_effect_refused=1 exact_publication_retry_original_commit_zero_effect=1 accepted_recovery_wrong_producer_zero_effect_refused=1 authenticated_actual_producer_mismatch_zero_effect_refused=1 revoked_content_source_fresh_issue_zero_effect_refused=1 completed_issue_replay_after_revoke_original=1 missing_authorization_ref_zero_effect_refused=1 selected_wrong_action_grant_zero_effect_refused=1 participation_closed_with_fresh_confirmation_zero_effect_refused=1 foreign_controller_sidecar_create_denied_zero_effect=1 canonical_case_completion_claim=0"
    );
    println!(
        "[agent-payload-approval] actual_valid_write_scope=1 selection_retained=1 private_request_accepted=1 exact_approval_missing=1 actual_403_claim_required=1 complete_business_noop=1 accepted_controller_confirmation=1 exact_original_publication_committed_and_read=1"
    );
    Ok(())
}

fn attributed_message(
    realm: &RealmId,
    strand: &arkret_wire::StrandId,
    owner: &AccountId,
    agent: &AgentPairedPrincipal,
    grant: Option<&arkret_wire::GrantId>,
    text: &str,
) -> Result<Event> {
    let payload: arkret_models_collaboration::events_payloads::message::MessageCreatePayload =
        serde_json::from_value(json!({
            "strand_id":strand,"track_name":"discussion","content":{"kind":"ak.content.text","body":text}
        }))?;
    let mut draft =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MessageCreate>::new(
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            ActorId::account(owner.clone()),
            payload,
        )?
        .with_executed_by(ActorId::account(agent.agent_account.clone()));
    if let Some(grant) = grant {
        draft = draft.with_authorization_ref(
            arkret_wire::AuthorizationRef::new(grant.as_str()).map_err(anyhow::Error::msg)?,
        );
    }
    sign(
        draft.author_with_digest_suite(Utc::now(), arkret_canonical::DigestSuite::Sha256)?,
        &agent.verification_method,
        agent.runtime_key.to_bytes(),
    )
}

async fn confirm_target(
    deployment: &coauth_session_evidence::ActualAgentDeployment,
    runtime: &TestActorClient,
    agent: &AgentPairedPrincipal,
    realm: &RealmId,
    strand: &arkret_wire::StrandId,
    target: &Event,
) -> Result<()> {
    let at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let request: arkret_models_collaboration::events_payloads::agent::AgentActionRequestPayload =
        serde_json::from_value(json!({
            "request_id":unique_uuid7(),"agent_id":agent.agent_account.principal_id,
            "controller_account_id":deployment.account,"proposed_action":"ak.message.create",
            "target":{"kind":"strand","realm_id":realm,"object_ref":strand},
            "request_canonical_digest":arkret_canonical::canonical_sha256(target)?,
            "expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::Duration::minutes(5)),
            "created_at":arkret_canonical::format_timestamp_canonical(at),
        }))?;
    let original = request.clone();
    let private = sign(
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::AgentActionRequest>::new(
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            ActorId::account(agent.agent_account.clone()),
            request,
        )?
        .author_with_digest_suite(at, arkret_canonical::DigestSuite::Sha256)?,
        &agent.verification_method,
        agent.runtime_key.to_bytes(),
    )?;
    let accepted = submit_actor_private(runtime, &private).await?;
    ensure!(
        accepted.status().is_success(),
        "exact private negative-case request failed: {} {}",
        accepted.status(),
        accepted.text().await?
    );
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow::anyhow!("confirmation nonce generation failed: {error}"))?;
    let approval = arkret_models_collaboration::events_payloads::agent::AgentActionApprovePayload {
        approval_id: unique_uuid7(),
        request_id: Some(original.request_id),
        draft_id: None,
        agent_id: agent.agent_account.principal_id.clone(),
        proposed_action: original.proposed_action,
        target: original.target,
        approved_event_id: target.event_id.clone(),
        draft_content_digest: None,
        approval_nonce: URL_SAFE_NO_PAD.encode(nonce),
        expires_at: at + chrono::Duration::minutes(2),
    };
    let event = deployment
        .controller
        .author_event(
            realm.as_str(),
            "ak.agent.action_approve",
            serde_json::to_value(approval)?,
        )
        .await?;
    expect_json(
        deployment
            .controller
            .post("/_arkret/self/events")
            .canonical_json(&arkret_wire::EventAdmissionSubmission::new(event))?,
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

async fn refuse_target(
    runtime: &TestActorClient,
    database: &str,
    event: &Event,
    expected: &[&str],
) -> Result<arkret_wire::Problem> {
    let before = acceptance_rows_with_agent_stores(database, true).await?;
    let response = runtime
        .post("/_arkret/self/events")
        .canonical_json(&arkret_wire::EventAdmissionSubmission::new(event.clone()))?
        .send()
        .await?;
    let status = response.status();
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        !status.is_success() && expected.contains(&problem.code()),
        "wrong publication refusal: {status} {problem:?}"
    );
    ensure!(
        before == acceptance_rows_with_agent_stores(database, true).await?,
        "denied publication changed business state"
    );
    Ok(problem)
}
