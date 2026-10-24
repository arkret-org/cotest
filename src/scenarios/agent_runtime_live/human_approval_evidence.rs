//! Accepted controller grants remediate a real Agent issuer approval refusal.

use arkret_models_collaboration::session_grants::{
    AgentSessionGrantRequestBody, SessionGrantResponseBody,
};

use super::coauth_session_evidence::issuer_state;
use super::*;
use crate::harness::CanonicalJsonBody;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

async fn send(
    station: &ArkretServer,
    url: &str,
    body: &AgentSessionGrantRequestBody,
    key: &SigningKey,
) -> Result<reqwest::Response> {
    let proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new("POST", url),
        key,
    )?;
    Ok(station
        .http()
        .post(url)
        .header("DPoP", proof.proof_jwt)
        .canonical_json(body)?
        .send()
        .await?)
}

pub async fn run_agent_human_approval_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    let deployment =
        coauth_session_evidence::actual_agent_deployment("agent-human-approval").await?;
    let station = &deployment.station;
    let controller = &deployment.controller;
    let created = controller
        .create_realm_with(json!({
            "title":"Controller-approved Agent session", "public":false, "join_rule":"public",
            "plaintext_visible_services":[station.service_id()]
        }))
        .await?;
    let realm = RealmId::new(created["realm_id"].as_str().context("Realm")?)?;
    let strand =
        arkret_wire::StrandId::new(created["default_strand_id"].as_str().context("Strand")?)?;
    let generation = EventId::new(
        created["event_response"]["commits"]
            .as_array()
            .and_then(|commits| commits.last())
            .and_then(|commit| commit["event_ref"].as_str())
            .context("controller join")?,
    )?;
    controller
        .grant_realm_actions_to(realm.as_str(), &controller.actor, &["ak.message.create"])
        .await?;
    let operations = arkret_schema::agent_runtime_scope::complete_agent_runtime_scope(
        [
            runtime_operations().as_slice(),
            &[
                ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                "ak.message.create",
            ],
        ]
        .concat(),
    )?;
    let refs = operations.iter().map(String::as_str).collect::<Vec<_>>();
    let mut scope = requested_scope(&refs)?;
    scope.resources.push(serde_json::from_value(
        json!({"kind":"strand","realm_id":realm,"resource_ref":strand}),
    )?);
    let agent = AgentRuntimeSession::establish_paired_observed(
        station,
        &AgentSessionIssuer::Coauth {
            base: deployment.coauth.base_url(),
            database_url: &deployment.coauth.pg.connect_url,
        },
        controller,
        &deployment.account,
        "approval-agent",
        scope,
        None,
    )
    .await?;
    let mut joined = MembershipPayload::join(
        realm.clone(),
        ActorId::account(agent.agent_account.clone()),
        "controller joins approval Agent",
    );
    joined.agent_controller_binding = Some(AgentControllerMembershipBinding {
        controller_account_id: deployment.account.clone(),
        controller_membership_generation_ref: generation,
        controller_terminal_event_ref: None,
    });
    controller
        .submit_event(realm.as_str(), "ak.member.state", joined.to_value()?)
        .await?;
    controller.submit_event(realm.as_str(), "ak.agent.interaction.set", serde_json::to_value(arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload {
        agent_account_id:agent.agent_account.clone(), controller_account_id:deployment.account.clone(),
        interaction_mode:arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public, expected_revision:None,
    })?).await?;
    controller
        .sdk()
        .agent_participation_replace(
            agent.agent_account.principal_id.as_str(),
            &arkret::ParticipationReplaceRequestBody {
                target_scope: arkret::ParticipationScope::Realm {
                    realm_id: realm.clone(),
                },
                selection: arkret::ParticipationBits {
                    ..arkret::ParticipationBits::NONE
                },
                expected_version: 0,
            },
        )
        .await?;
    let url = format!(
        "{}/_arkret/gate/account/session-grants",
        deployment.coauth.base_url()
    );
    let database = station
        .owned_database_url()
        .context("owned Station database")?
        .to_owned();
    let issuer_url = &deployment.coauth.pg.connect_url;
    let intent = coauth_session_evidence::build_runtime_session_request(
        station,
        deployment.coauth.base_url(),
        &agent.agent_account.principal_id,
        &agent.key_authorization,
        &agent.verification_method,
        &agent.runtime_key,
        &operations.iter().map(String::as_str).collect::<Vec<_>>(),
        serde_json::from_value(json!({"strand_ids":[strand],"track_names":["discussion"]}))?,
    )?;
    let first = coauth_session_evidence::fresh_session_request(&intent, &url, &agent.runtime_key)?;
    let before_station = acceptance_rows_with_agent_stores(&database, true).await?;
    let before_issuer = issuer_state(issuer_url).await?;
    coauth_session_evidence::expect_issue_refusal(
        station,
        issuer_url,
        &url,
        &first,
        &agent.runtime_key,
        None,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
        None,
    )
    .await?;
    ensure!(
        before_issuer == issuer_state(issuer_url).await?
            && before_station == acceptance_rows_with_agent_stores(&database, true).await?
    );
    controller
        .sdk()
        .agent_participation_replace(
            agent.agent_account.principal_id.as_str(),
            &arkret::ParticipationReplaceRequestBody {
                target_scope: arkret::ParticipationScope::Realm {
                    realm_id: realm.clone(),
                },
                selection: arkret::ParticipationBits {
                    message_creation_allowed: true,
                    ..arkret::ParticipationBits::NONE
                },
                expected_version: 1,
            },
        )
        .await?;
    let first = coauth_session_evidence::fresh_session_request(&intent, &url, &agent.runtime_key)?;
    let before_station = acceptance_rows_with_agent_stores(&database, true).await?;
    let before_issuer = issuer_state(issuer_url).await?;
    let mut bad_proof = first.clone();
    bad_proof.proof.signature = "A".repeat(86);
    coauth_session_evidence::expect_issue_refusal(
        station,
        issuer_url,
        &url,
        &bad_proof,
        &agent.runtime_key,
        None,
        arkret_wire::ErrorCode::SIGNATURE_INVALID,
        Some(arkret_wire::ReasonCode::PROOF_INVALID),
    )
    .await?;
    ensure!(
        before_issuer == issuer_state(issuer_url).await?
            && before_station == acceptance_rows_with_agent_stores(&database, true).await?
    );
    let response = send(station, &url, &first, &agent.runtime_key).await?;
    ensure!(
        response.status() == StatusCode::FORBIDDEN,
        "missing grant did not require approval: {} {}",
        response.status(),
        response.text().await?
    );
    let media = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let value: serde_json::Value = response.json().await?;
    let problem: arkret_wire::Problem = serde_json::from_value(value.clone())?;
    coauth_session_evidence::validate_issue_problem(&problem)?;
    ensure!(
        media.starts_with("application/problem+json")
            && problem.code() == arkret_wire::ErrorCode::CLAIM_REQUIRED
            && problem.status == 403
    );
    let approval = problem
        .agent_human_approval_details()?
        .context("closed human approval extension")?;
    ensure!(problem.extensions.len() == 2 && !approval.approval_request_id().is_empty());
    let mut opaque_as_authority = serde_json::to_value(&first)?;
    opaque_as_authority["approval_evidence_refs"] = json!([approval.approval_request_id()]);
    let http_proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new("POST", &url),
        &agent.runtime_key,
    )?;
    let refused = station
        .http()
        .post(&url)
        .header("DPoP", http_proof.proof_jwt)
        .canonical_json(&opaque_as_authority)?
        .send()
        .await?;
    ensure!(refused.status().is_client_error());
    let refused: arkret_wire::Problem = refused.json().await?;
    coauth_session_evidence::validate_issue_problem(&refused)?;
    ensure!(
        refused.code() != arkret_wire::ErrorCode::CLAIM_REQUIRED,
        "correlation handle was interpreted as approval authority"
    );
    ensure!(
        value.get("captcha").is_none()
            && value.get("otp").is_none()
            && value.get("browser_redirect").is_none()
            && value.get("password_prompt").is_none()
    );
    ensure!(
        before_issuer == issuer_state(issuer_url).await?
            && before_station == acceptance_rows_with_agent_stores(&database, true).await?,
        "approval refusal wrote issuer or Station state"
    );
    for reference in [
        agent.key_authorization.clone(),
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x75; 32]),
    ] {
        let mut wrong = intent.clone();
        wrong.approval_evidence_refs = Some(vec![reference]);
        let wrong =
            coauth_session_evidence::fresh_session_request(&wrong, &url, &agent.runtime_key)?;
        coauth_session_evidence::expect_issue_refusal(
            station,
            issuer_url,
            &url,
            &wrong,
            &agent.runtime_key,
            None,
            arkret_wire::ErrorCode::CAPABILITY_DENIED,
            None,
        )
        .await?;
        ensure!(
            before_issuer == issuer_state(issuer_url).await?
                && before_station == acceptance_rows_with_agent_stores(&database, true).await?
        );
    }
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
        constraints: vec![serde_json::from_value(
            json!({"constraint_kind":"scope_limitation","effect":"allow","allowed_strand_ids":[strand],"allowed_tracks":["discussion"]}),
        )?],
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
                    grant: body,
                },
            )?,
        )
        .await?;
    let reference = grant.event_id.clone();
    let grant_id = arkret_wire::GrantId::from_event_id(&reference);
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        controller,
        &deployment.account,
        &controller.device_id,
        &grant,
    )
    .await?;
    let accepted = controller.sdk().committed_event_get(&reference).await?;
    ensure!(
        accepted.reducer_input() == Some(&grant),
        "controller approval Event changed at admission"
    );
    let mut retry = intent.clone();
    retry.approval_evidence_refs = Some(vec![reference.clone()]);
    let retry = coauth_session_evidence::fresh_session_request(&retry, &url, &agent.runtime_key)?;
    ensure!(
        retry.proof.challenge != first.proof.challenge
            && retry.proof.request_canonical_digest != first.proof.request_canonical_digest
    );
    let response = send(station, &url, &retry, &agent.runtime_key).await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    ensure!(
        status.is_success(),
        "accepted approval retry failed: {status} {}",
        String::from_utf8_lossy(&bytes)
    );
    let issued: SessionGrantResponseBody = serde_json::from_slice(&bytes)?;
    ensure!(
        issued.device_id.is_none()
            && issued
                .granted_scope
                .contains(&"ak.message.create".to_owned())
    );
    let runtime = station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "approved-content-runtime",
        issued.session_grant.clone(),
        agent.runtime_key.clone(),
    )?;
    let message =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MessageCreate>::new(
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            ActorId::account(agent.agent_account.clone()),
            arkret_models_collaboration::events_payloads::MessageCreatePayload::with_content(
                strand.clone(),
                "discussion",
                arkret_models_collaboration::events_payloads::ContentBlock::text(
                    "Controller approved this exact content scope",
                ),
            ),
        )?
        .with_semantic_ref(arkret_wire::SemanticRef::new(
            grant_id.to_string(),
            arkret_wire::SEMANTIC_REF_ROLE_AUTHORIZED_BY,
        ))
        .author_with_digest_suite(Utc::now(), arkret_canonical::DigestSuite::Sha256)?;
    let message = sign(
        message,
        &agent.verification_method,
        agent.runtime_key.to_bytes(),
    )?;
    let outcome: AuthoritySubmitResponseBody = serde_json::from_value(
        expect_json(
            runtime
                .post("/_arkret/self/events")
                .canonical_json(&arkret_wire::EventAdmissionSubmission::new(message.clone()))?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(outcome,AuthoritySubmitResponseBody::Accepted {status:AuthorityCommitStatus::Committed,commit} if commit.event_ref==message.event_id)
    );
    controller
        .revoke_realm_grant(realm.as_str(), grant_id.as_str())
        .await?;
    let revoked = acceptance_rows_with_agent_stores(&database, true).await?;
    let issuer = issuer_state(issuer_url).await?;
    let rejected =
        coauth_session_evidence::fresh_session_request(&retry, &url, &agent.runtime_key)?;
    coauth_session_evidence::expect_issue_refusal(
        station,
        issuer_url,
        &url,
        &rejected,
        &agent.runtime_key,
        None,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
        None,
    )
    .await?;
    ensure!(
        issuer == issuer_state(issuer_url).await?
            && revoked == acceptance_rows_with_agent_stores(&database, true).await?
    );
    let response = send(station, &url, &retry, &agent.runtime_key).await?;
    ensure!(response.status().is_success());
    ensure!(
        response.bytes().await? == bytes,
        "completed retry recomputed approved authority"
    );
    ensure!(
        issuer == issuer_state(issuer_url).await?
            && revoked == acceptance_rows_with_agent_stores(&database, true).await?
    );
    let root = crate::scenarios::_helpers::external_binary::workspace_root()
        .context("source workspace")?;
    let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(
        root.join("arkret-spec/spec/v1/artifacts/fixtures/agent-vectors-fixture.json"),
    )?)?;
    let cases = fixture["cases"]
        .as_array()
        .context("Agent canonical cases")?
        .iter()
        .filter(|case| case["name"] == "agent_human_approval_required")
        .collect::<Vec<_>>();
    let [case] = cases.as_slice() else {
        bail!("human approval case not unique")
    };
    let assertions = case["assertions"]
        .as_array()
        .context("human approval assertions")?
        .iter()
        .map(|v| v.as_str().context("assertion text"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        assertions
            == [
                "RFC 9457 extension members validate against agent_human_approval_problem_extensions",
                "approval_request_id is opaque and is the only runtime-visible correlation handle",
                "controller approval completes out of band",
                "agent retry references accepted approval evidence",
                "no interactive human challenge is returned to the agent runtime"
            ]
    );
    println!(
        "[agent-human-approval] real_issuer_rfc9457=1 opaque_correlation_only=1 no_interactive_runtime_challenge=1 refusal_full_issuer_and_station_unchanged=1 controller_device_original_event_accepted=1 signed_retry_exact_current_grant_ref=1 actual_content_committed=1 wrong_kind_unknown_revoked_refs_zero_effect=1 completed_retry_original_after_revoke=1 observations=5"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: "agent_human_approval_required".to_owned(),
            assertions: 5,
        }],
    })
}
