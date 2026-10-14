//! Actual controller transitions and the terminal runtime-session barrier.

use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentLifecycleOutcome, AgentLifecycleState, AgentPauseRequestBody,
    AgentReadinessBlocker, AgentReadinessState, AgentResumeRequestBody, AgentView,
};

use super::*;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

fn request(
    controller: &TestActorClient,
    agent: &AgentRuntimeSession,
    action: &str,
) -> Result<(Event, Vec<u8>)> {
    let principal = controller
        .principal
        .as_ref()
        .context("accepted controller")?;
    let method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    let actor = ActorId::account(agent.agent_account.clone());
    let executor = ActorId::account(agent.controller_account.clone());
    let scope = ScopeRef::Realm {
        realm_id: agent.agent_pcr.clone(),
    };
    let intent = match action {
        "pause" => arkret_event_draft::build_agent_pause_intent(
            actor,
            executor,
            scope,
            agent.delegation.clone(),
            None,
            Utc::now(),
        )?,
        "resume" => arkret_event_draft::build_agent_resume_intent(
            actor,
            executor,
            scope,
            agent.delegation.clone(),
            Utc::now(),
        )?,
        "deactivate" => arkret_event_draft::build_agent_deactivate_intent(
            actor,
            executor,
            scope,
            agent.delegation.clone(),
            arkret_event_draft::AgentLifecycleState::Active,
            None,
            Utc::now(),
        )?,
        _ => bail!("unregistered lifecycle action"),
    };
    let event = sign(
        intent.author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &method,
        principal.device_signing_key.to_bytes(),
    )?;
    let submission = arkret_wire::EventAdmissionSubmission::new(event.clone());
    let bytes = match action {
        "pause" => arkret_canonical::canonical_json_bytes(&AgentPauseRequestBody {
            reason: None,
            lifecycle_event: submission,
        })?,
        "resume" => arkret_canonical::canonical_json_bytes(&AgentResumeRequestBody {
            lifecycle_event: submission,
        })?,
        _ => arkret_canonical::canonical_json_bytes(&AgentDeactivateRequestBody {
            reason: None,
            lifecycle_event: submission,
        })?,
    };
    Ok((event, bytes))
}

async fn view(controller: &TestActorClient, agent: &AgentRuntimeSession) -> Result<AgentView> {
    Ok(serde_json::from_value(
        expect_json(
            controller.get(&format!(
                "/_arkret/self/agents/{}",
                agent.agent_account.principal_id
            )),
            StatusCode::OK,
        )
        .await?,
    )?)
}

async fn accepted(
    station: &ArkretServer,
    controller: &TestActorClient,
    agent: &AgentRuntimeSession,
    url: &str,
    action: &str,
    expected: AgentLifecycleState,
) -> Result<Vec<u8>> {
    let before = acceptance_rows_with_agent_stores(url, true).await?;
    let (event, bytes) = request(controller, agent, action)?;
    let outcome: AgentLifecycleOutcome = serde_json::from_value(
        expect_json(
            controller
                .post(&format!(
                    "/_arkret/self/agents/{}/{action}",
                    agent.agent_account.principal_id
                ))
                .header("Content-Type", "application/json")
                .body(bytes.clone()),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(outcome.status == expected);
    let after = acceptance_rows_with_agent_stores(url, true).await?;
    let persisted = after["canonical_events"]
        .as_array()
        .context("accepted Events")?
        .iter()
        .find(|row| {
            row["envelope"]["event_id"].as_str() == Some(event.event_id.as_str())
                && row["state"] == "committed"
        })
        .context("original lifecycle Event was not persisted")?;
    let original: Event = serde_json::from_value(persisted["envelope"].clone())?;
    let covering = after["realm_commits"]
        .as_array()
        .context("accepted Commits")?
        .iter()
        .find(|row| row["commit_json"]["event_ref"].as_str() == Some(event.event_id.as_str()))
        .context("original lifecycle Event has no covering Commit")?;
    let commit: arkret_wire::RealmCommit = serde_json::from_value(covering["commit_json"].clone())?;
    commit.validate_content_address()?;
    crate::scenarios::human_device_producer_live::ensure_commit_signed_by(&commit, station)?;
    ensure!(
        original == event
            && commit.event_ref == event.event_id
            && commit.stream_ref
                == (arkret_wire::CommitStreamRef::Realm {
                    realm_id: agent.agent_pcr.clone()
                })
    );
    for table in ["canonical_events", "realm_commits"] {
        ensure!(
            after[table].as_array().context("accepted rows")?.len()
                == before[table].as_array().context("original rows")?.len() + 1,
            "{action} accepted additional child revocation Events or Commits"
        );
    }
    let current = view(controller, agent).await?;
    ensure!(current.agent.lifecycle == expected);
    ensure!(
        current
            .agent
            .readiness
            .blockers
            .iter()
            .all(|blocker| matches!(
                blocker,
                AgentReadinessBlocker::RuntimeKeyMissing | AgentReadinessBlocker::PairingOpen
            ))
    );
    ensure!(current.agent.presence.refresh_after <= current.agent.presence.expires_at);
    println!(
        "[agent-lifecycle] transition={action} exact_original_event_commit=1 single_accepted_event=1 orthogonal_projection=1"
    );
    Ok(bytes)
}

async fn replay_lifecycle(
    controller: &TestActorClient,
    agent: &AgentRuntimeSession,
    url: &str,
    bytes: &[u8],
    current: AgentLifecycleState,
    action: &str,
    original: AgentLifecycleState,
) -> Result<()> {
    let before = acceptance_rows_with_agent_stores(url, true).await?;
    let outcome: AgentLifecycleOutcome = serde_json::from_value(
        expect_json(
            controller
                .post(&format!(
                    "/_arkret/self/agents/{}/{action}",
                    agent.agent_account.principal_id
                ))
                .header("Content-Type", "application/json")
                .body(bytes.to_vec()),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(outcome.status == original);
    ensure!(acceptance_rows_with_agent_stores(url, true).await? == before);
    ensure!(view(controller, agent).await?.agent.lifecycle == current);
    println!(
        "[agent-lifecycle] original_retry={action} current={current:?} full_footprint_unchanged=1"
    );
    Ok(())
}

async fn refused(
    controller: &TestActorClient,
    agent: &AgentRuntimeSession,
    url: &str,
    action: &str,
    reason: &str,
) -> Result<()> {
    let before = acceptance_rows_with_agent_stores(url, true).await?;
    let (_, bytes) = request(controller, agent, action)?;
    let response = controller
        .post(&format!(
            "/_arkret/self/agents/{}/{action}",
            agent.agent_account.principal_id
        ))
        .header("Content-Type", "application/json")
        .body(bytes)
        .send()
        .await?;
    ensure!(response.status().is_client_error());
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        problem
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str)
            == Some(reason),
        "{action} refusal missed {reason}: {problem:?}"
    );
    ensure!(
        acceptance_rows_with_agent_stores(url, true).await? == before,
        "{action} refusal changed full accepted state"
    );
    println!("[agent-lifecycle] refused={action} reason={reason} full_footprint_unchanged=1");
    Ok(())
}

pub async fn run_agent_controller_lifecycle_boundary() -> Result<()> {
    registry_bindings()?;
    let name = "agent-controller-lifecycle-production";
    let database = database(name)?.context("real PostgreSQL required")?;
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        name,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    .context("actual Station required")?;
    let station = group.server(0);
    let (controller, account) =
        standard_client(station, &coauth, "lifecycle-controller", CONTROLLER_DEVICE).await?;
    let agent =
        AgentRuntimeSession::establish(station, &coauth, &controller, &account, "lifecycle-agent")
            .await?;
    let initial = view(&controller, &agent).await?;
    ensure!(
        initial.agent.lifecycle == AgentLifecycleState::Active
            && initial.agent.readiness.state == AgentReadinessState::Ready
            && initial.agent.readiness.blockers.is_empty()
    );
    let key_before = initial.key_state.context("accepted current key")?;
    let pause_request = accepted(
        station,
        &controller,
        &agent,
        &database.connect_url,
        "pause",
        AgentLifecycleState::Paused,
    )
    .await?;
    replay_lifecycle(
        &controller,
        &agent,
        &database.connect_url,
        &pause_request,
        AgentLifecycleState::Paused,
        "pause",
        AgentLifecycleState::Paused,
    )
    .await?;
    refused(
        &controller,
        &agent,
        &database.connect_url,
        "pause",
        arkret_wire::ReasonCode::AGENT_PAUSED,
    )
    .await?;
    let paused = view(&controller, &agent).await?;
    ensure!(
        paused.agent.readiness.state == AgentReadinessState::Ready
            && serde_json::to_value(
                &paused
                    .key_state
                    .as_ref()
                    .context("paused durable key state")?
                    .active_authorizations,
            )? == serde_json::to_value(&key_before.active_authorizations)?,
        "pause erased the independent durable key or readiness axis"
    );
    accepted(
        station,
        &controller,
        &agent,
        &database.connect_url,
        "resume",
        AgentLifecycleState::Active,
    )
    .await?;
    replay_lifecycle(
        &controller,
        &agent,
        &database.connect_url,
        &pause_request,
        AgentLifecycleState::Active,
        "pause",
        AgentLifecycleState::Paused,
    )
    .await?;
    let (_, bytes) = request(&controller, &agent, "deactivate")?;
    let mut bundle: serde_json::Value = serde_json::from_slice(&bytes)?;
    bundle["key_revocations"] = json!([]);
    bundle["grant_revocations"] = json!([]);
    let before = acceptance_rows_with_agent_stores(&database.connect_url, true).await?;
    let response = controller
        .post(&format!(
            "/_arkret/self/agents/{}/deactivate",
            agent.agent_account.principal_id
        ))
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(&bundle)?)
        .send()
        .await?;
    ensure!(
        response.status().is_client_error(),
        "client-authored revocation bundle was accepted"
    );
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(problem.code() == arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    ensure!(acceptance_rows_with_agent_stores(&database.connect_url, true).await? == before);
    let terminal_started = Instant::now();
    let deactivate_request = accepted(
        station,
        &controller,
        &agent,
        &database.connect_url,
        "deactivate",
        AgentLifecycleState::Deactivated,
    )
    .await?;
    replay_lifecycle(
        &controller,
        &agent,
        &database.connect_url,
        &pause_request,
        AgentLifecycleState::Deactivated,
        "pause",
        AgentLifecycleState::Paused,
    )
    .await?;
    replay_lifecycle(
        &controller,
        &agent,
        &database.connect_url,
        &deactivate_request,
        AgentLifecycleState::Deactivated,
        "deactivate",
        AgentLifecycleState::Deactivated,
    )
    .await?;
    let mut changed: serde_json::Value = serde_json::from_slice(&pause_request)?;
    let proof = changed
        .pointer_mut("/lifecycle_event/event/producer_proof/jws")
        .context("original controller proof")?;
    let mut bytes = proof.as_str().context("original JWS")?.as_bytes().to_vec();
    let position = bytes
        .iter()
        .rposition(|byte| *byte == b'.')
        .context("JWS signature")?
        + 1;
    bytes[position] = if bytes[position] == b'A' { b'B' } else { b'A' };
    *proof = json!(String::from_utf8(bytes)?);
    let before = acceptance_rows_with_agent_stores(&database.connect_url, true).await?;
    let response = controller
        .post(&format!(
            "/_arkret/self/agents/{}/pause",
            agent.agent_account.principal_id
        ))
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(&changed)?)
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::CONFLICT,
        "changed original proof bypassed exact replay identity"
    );
    let _: arkret_wire::Problem = response.json().await?;
    ensure!(acceptance_rows_with_agent_stores(&database.connect_url, true).await? == before);
    println!("[agent-lifecycle] changed_original_proof_conflict=1 full_footprint_unchanged=1");
    refused(
        &controller,
        &agent,
        &database.connect_url,
        "resume",
        arkret_wire::ReasonCode::AGENT_DEACTIVATED,
    )
    .await?;
    let deadline = terminal_started + Duration::from_secs(60);
    loop {
        let response = agent
            .runtime
            .get("/_arkret/self/device_messages")
            .send()
            .await?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            let _: arkret_wire::Problem = response.json().await?;
            ensure!(
                Instant::now() <= deadline,
                "terminal rejection exceeded sixty seconds from transition submission"
            );
            break;
        }
        ensure!(
            response.status() == StatusCode::OK && Instant::now() < deadline,
            "terminal runtime session exceeded the 60s freshness barrier"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!(
        "[agent-lifecycle] controller_transitions_verified=1 terminal_existing_session_refused_within_60s=1 canonical_case_completion_claim=0"
    );
    Ok(())
}

fn registry_bindings() -> Result<()> {
    let root = crate::scenarios::_helpers::external_binary::workspace_root()
        .context("binding source workspace")?;
    let registry: serde_json::Value = serde_json::from_slice(&std::fs::read(
        root.join("arkret-spec/spec/v1/artifacts/registry/contract-registry.json"),
    )?)?;
    let operations = registry
        .pointer("/operation_registry/operations")
        .and_then(serde_json::Value::as_array)
        .context("normative operation registry")?;
    for token in [
        ServiceOperationId::SELF_AGENT_COMMAND_PAUSE_V1,
        ServiceOperationId::SELF_AGENT_COMMAND_RESUME_V1,
        ServiceOperationId::SELF_AGENT_COMMAND_DEACTIVATE_V1,
        ServiceOperationId::SELF_AGENT_COMMAND_RENEW_PAIRING_V1,
        ServiceOperationId::SELF_AGENT_READ_LIST_V1,
        ServiceOperationId::SELF_AGENT_RESOURCE_GET_V1,
        ServiceOperationId::SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1,
    ] {
        let descriptor = ServiceOperationId::from_wire(token)
            .context("registered SDK operation")?
            .descriptor();
        let matches = operations
            .iter()
            .filter(|operation| operation["operation_id"].as_str() == Some(token))
            .collect::<Vec<_>>();
        let [operation] = matches.as_slice() else {
            bail!("lifecycle operation is not uniquely registered: {token}");
        };
        ensure!(
            operation["http"].as_str()
                == Some(format!("{} {}", descriptor.http_method, descriptor.http_path).as_str()),
            "lifecycle HTTP binding differs from normative registry: {token}"
        );
        ensure!(
            operation["request_schema_ref"].as_str() == descriptor.request_schema_ref
                && operation["response_schema_ref"].as_str() == descriptor.response_schema_ref,
            "lifecycle DTO binding differs from normative registry: {token}"
        );
    }
    println!("[agent-lifecycle] normative_registry_exact_operation_http_dto_bindings=7");
    Ok(())
}
