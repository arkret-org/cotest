//! Real replacement handles, exact authorization dots and superseded sessions.

use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentPauseRequestBody, AgentRenewPairingRequestBody,
    AgentResumeRequestBody, AgentView,
};
use arkret_models_collaboration::events_payloads::agent::AgentKeySupersession;
use serde_json::Value;

use super::*;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

async fn authority_facts(url: &str) -> Result<Value> {
    let snapshot = acceptance_rows_with_agent_stores(url, true).await?;
    let mut facts = serde_json::Map::new();
    for table in [
        "canonical_events",
        "realm_commits",
        "agent_status_current_states",
        "agent_key_current_states",
        "capability_grant_current_states",
    ] {
        facts.insert(
            table.to_owned(),
            snapshot
                .get(table)
                .with_context(|| format!("authority snapshot has no {table}"))?
                .clone(),
        );
    }
    Ok(Value::Object(facts))
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

fn supersedes_request(
    material: &pairing_expiry_evidence::ReplacementMaterial,
    controller: &TestActorClient,
    agent: &AgentRuntimeSession,
    supersedes: Vec<AgentKeySupersession>,
) -> Result<arkret_models_collaboration::agent_scope::AgentKeyPairRequestBody> {
    let principal = controller
        .principal
        .as_ref()
        .context("accepted controller")?;
    let method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    let mut payload = AgentKeyAuthorizePayload::try_from(&material.body.authorize_event.event)?;
    payload.supersedes = supersedes;
    let event = sign(
        arkret_event_draft::build_agent_key_authorize_intent(
            &payload,
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            ActorId::account(agent.agent_account.clone()),
            ActorId::account(agent.controller_account.clone()),
            agent.delegation.clone(),
            Utc::now(),
        )?
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &method,
        principal.device_signing_key.to_bytes(),
    )?;
    let mut body = material.body.clone();
    body.authorize_event = arkret_wire::EventAdmissionSubmission::new(event);
    Ok(body)
}

async fn refused_supersedes(
    controller: &TestActorClient,
    url: &str,
    body: &arkret_models_collaboration::agent_scope::AgentKeyPairRequestBody,
    label: &str,
) -> Result<()> {
    let before = acceptance_rows_with_agent_stores(url, true).await?;
    let response = controller
        .post("/_arkret/gate/account/agent-key-pair")
        .header(
            "Idempotency-Key",
            body.authorize_event.event.event_id.as_str(),
        )
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(body)?)
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::CONFLICT,
        "{label} supersedes reached the wrong status: {}",
        response.status()
    );
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        problem.code() == arkret_wire::ErrorCode::FAILED_PRECONDITION
            && problem.detail.contains("supersedes"),
        "{label} missed the exact supersedes decision: {problem:?}"
    );
    ensure!(
        acceptance_rows_with_agent_stores(url, true).await? == before,
        "{label} supersedes refusal changed full accepted/Agent state"
    );
    let conn_url = url.to_owned();
    let event_id = body.authorize_event.event.event_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut db = postgres::Client::connect(&conn_url, postgres::NoTls)?;
        let count: i64 = db.query_one(
            "SELECT count(*) FROM audit_logs WHERE action='ak.agent.key.authorize' AND outcome='accepted' AND payload->>'event_id'=$1",
            &[&event_id],
        )?.get(0);
        ensure!(count == 0, "refused replacement left an accepted reducer audit");
        Ok(())
    }).await??;
    println!("[agent-repairing] rejected_supersedes={label} full_business_footprint_unchanged=1");
    Ok(())
}

pub(super) async fn lifecycle(
    controller: &TestActorClient,
    agent: &AgentRuntimeSession,
    action: &str,
) -> Result<()> {
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
        _ => bail!("unsupported lifecycle action"),
    };
    let submission = arkret_wire::EventAdmissionSubmission::new(sign(
        intent.author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &method,
        principal.device_signing_key.to_bytes(),
    )?);
    let url = format!(
        "/_arkret/self/agents/{}/{action}",
        agent.agent_account.principal_id
    );
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
    expect_json(
        controller
            .post(&url)
            .header("Content-Type", "application/json")
            .body(bytes),
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

pub async fn run_agent_repairing_production() -> Result<crate::conformance::SuiteExecutionResult> {
    let name = "agent-repairing-production";
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
        standard_client(station, &coauth, "repairing-controller", CONTROLLER_DEVICE).await?;
    let agent =
        AgentRuntimeSession::establish(station, &coauth, &controller, &account, "repairing-agent")
            .await?;
    lifecycle(&controller, &agent, "pause").await?;
    let paused = authority_facts(&database.connect_url).await?;
    let first =
        pairing_expiry_evidence::replacement_material(station, &controller, &account, &agent)
            .await?;
    ensure!(
        authority_facts(&database.connect_url).await? == paused,
        "paused renewal changed lifecycle, keys, grants or accepted Events"
    );
    let first_token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
        &json!({"r": first.bootstrap.pairing_request_id, "c":first.bootstrap.pairing_code}),
    )?);
    ensure!(
        first.bootstrap.pairing_code.len() == 8
            && first
                .bootstrap
                .pairing_code
                .bytes()
                .all(|byte| byte.is_ascii_digit()),
        "renewed pairing code is not exactly eight ASCII digits"
    );
    let code_only = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
        &json!({"c":first.bootstrap.pairing_code}),
    )?);
    let code_only_response = station
        .http()
        .post(station.url("/_arkret/open/agent-pairing/resolve"))
        .json(
            &arkret_models_collaboration::agent_operations::AgentPairingResolveRequestBody {
                pairing_token: code_only,
            },
        )
        .send()
        .await?;
    ensure!(
        code_only_response.status().is_client_error(),
        "the pairing code alone resolved a request"
    );
    lifecycle(&controller, &agent, "resume").await?;
    let active = authority_facts(&database.connect_url).await?;
    let pending =
        pairing_expiry_evidence::replacement_material(station, &controller, &account, &agent)
            .await?;
    ensure!(
        pending.bootstrap.pairing_request_id != first.bootstrap.pairing_request_id
            && pending.bootstrap.pairing_code.len() == 8
            && pending
                .bootstrap
                .pairing_code
                .bytes()
                .all(|byte| byte.is_ascii_digit()),
        "renewal reused its handle or returned an invalid code"
    );
    ensure!(
        authority_facts(&database.connect_url).await? == active,
        "active renewal changed authority before pairing"
    );
    for _ in 0..2 {
        let response = station
            .http()
            .post(station.url("/_arkret/open/agent-pairing/resolve"))
            .header("Content-Type", "application/json")
            .body(arkret_canonical::canonical_json_bytes(
                &arkret_models_collaboration::agent_operations::AgentPairingResolveRequestBody {
                    pairing_token: first_token.clone(),
                },
            )?)
            .send()
            .await?;
        ensure!(
            response.status() == StatusCode::NOT_FOUND,
            "superseded pairing handle resolved again"
        );
    }
    let wait = pending
        .bootstrap
        .pairing_expires_at
        .signed_duration_since(Utc::now())
        .to_std()
        .unwrap_or_default();
    ensure!(
        wait <= Duration::from_secs(9),
        "unexpected long pairing TTL"
    );
    tokio::time::sleep(wait + Duration::from_millis(50)).await;
    let after_expiry = view(&controller, &agent).await?;
    ensure!(
        after_expiry.agent.lifecycle
            == arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
            && after_expiry.agent.readiness.blockers.is_empty()
            && after_expiry
                .key_state
                .as_ref()
                .context("accepted key state")?
                .active_authorizations
                .iter()
                .any(|dot| dot.authorized_event_ref == agent.key_authorization),
        "replacement expiry removed a current key or yielded a readiness blocker"
    );
    ensure!(
        authority_facts(&database.connect_url).await? == active,
        "unused replacement expiry changed accepted authority"
    );
    ensure!(
        agent
            .runtime
            .get("/_arkret/self/device_messages")
            .send()
            .await?
            .status()
            == StatusCode::OK,
        "unused replacement expiry invalidated the old session"
    );

    let replacement =
        pairing_expiry_evidence::replacement_material(station, &controller, &account, &agent)
            .await?;
    let original =
        AgentKeyAuthorizePayload::try_from(&replacement.body.authorize_event.event)?.supersedes;
    let wrong_ref = controller
        .principal
        .as_ref()
        .context("controller")?
        .founding_authorize_event_id
        .clone();
    let mut extra = original.clone();
    extra.push(AgentKeySupersession {
        key_id: NonEmptyString::new("unknown-runtime-key").map_err(anyhow::Error::msg)?,
        authorized_event_ref: wrong_ref.clone(),
    });
    let mut wrong = original.clone();
    wrong[0].authorized_event_ref = wrong_ref;
    for (label, set) in [
        ("partial", Vec::new()),
        ("extra", extra),
        ("wrong_authorized_event_ref", wrong),
    ] {
        let invalid = supersedes_request(&replacement, &controller, &agent, set)?;
        refused_supersedes(&controller, &database.connect_url, &invalid, label).await?;
    }
    let paired: AgentKeyPairResponseBody = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/gate/account/agent-key-pair")
                .header(
                    "Idempotency-Key",
                    replacement.body.authorize_event.event.event_id.as_str(),
                )
                .header("Content-Type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(&replacement.body)?),
            StatusCode::OK,
        )
        .await?,
    )?;
    wait_for_activation(
        station,
        &replacement.bootstrap,
        &replacement.bootstrap.pairing_code,
        &agent.agent_account.principal_id,
        &paired.authorize_event_ref,
    )
    .await?;
    let replay: AgentKeyPairResponseBody = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/gate/account/agent-key-pair")
                .header(
                    "Idempotency-Key",
                    replacement.body.authorize_event.event.event_id.as_str(),
                )
                .header("Content-Type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(&replacement.body)?),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        replay.authorize_event_ref == paired.authorize_event_ref
            && replay.activation_state == arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::Active,
        "exact pairing retry did not recover the same activated command"
    );
    let replaced = view(&controller, &agent).await?;
    let dots = &replaced
        .key_state
        .as_ref()
        .context("replacement key state")?
        .active_authorizations;
    ensure!(
        dots.len() == 1
            && dots[0].authorized_event_ref == paired.authorize_event_ref
            && dots[0].verification_method
                == replacement
                    .bootstrap
                    .validated_runtime_identity()
                    .map_err(anyhow::Error::msg)?
                    .verification_method,
        "replacement did not atomically replace the exact old dot"
    );
    let conn_url = database.connect_url.clone();
    let superseded = serde_json::to_value(&original)?;
    let replacement_ref = paired.authorize_event_ref.to_string();
    let expected_agent = agent.agent_account.principal_id.to_string();
    let expected_realm = agent.agent_pcr.to_string();
    let expected_executor =
        serde_json::to_value(ActorId::account(agent.controller_account.clone()))?;
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut db = postgres::Client::connect(&conn_url, postgres::NoTls)?;
        let rows = db.query("SELECT payload FROM audit_logs WHERE action='ak.agent.key.authorize' AND outcome='accepted' AND payload->>'event_id'=$1", &[&replacement_ref])?;
        let committed: Value = db.query_one(
            "SELECT c.commit_json FROM realm_commits c JOIN canonical_events e ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1",
            &[&replacement_ref],
        )?.get(0);
        let commit: arkret_wire::RealmCommit = serde_json::from_value(committed)?;
        ensure!(
            rows.len() == 1 && rows.iter().any(|row| {
                let value: Value = row.get(0);
                value.get("supersedes") == Some(&superseded)
                    && value.get("commit_id") == Some(&serde_json::to_value(&commit.commit_id).expect("typed commit id"))
                    && value.get("agent_id").and_then(Value::as_str) == Some(expected_agent.as_str())
                    && value.get("realm_id").and_then(Value::as_str) == Some(expected_realm.as_str())
                    && value.get("executed_by") == Some(&expected_executor)
                    && value.get("reason_code").and_then(Value::as_str)
                        == Some(arkret_wire::ReasonCode::SUPERSEDED_BY_REPAIRING)
            }),
            "replacement lacks its unique exact-set superseded_by_repairing reducer audit"
        );
        Ok(())
    })
    .await??;
    let method = replacement
        .bootstrap
        .validated_runtime_identity()
        .map_err(anyhow::Error::msg)?
        .verification_method
        .clone();
    let payload = AgentKeyAuthorizePayload::try_from(&replacement.body.authorize_event.event)?;
    let grant = crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt(
        agent.agent_account.principal_id.as_str(),
        method.as_str(),
        station.service_id().as_str(),
    );
    coauth.bind_agent_runtime_grant(
        &grant,
        &paired.authorize_event_ref,
        &payload,
        &replacement.key.verifying_key(),
    )?;
    let current = station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "replacement-runtime",
        grant,
        replacement.key.clone(),
    )?;
    ensure!(
        current
            .get("/_arkret/self/device_messages")
            .send()
            .await?
            .status()
            == StatusCode::OK,
        "replacement runtime cannot use its accepted key"
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let response = agent
            .runtime
            .get("/_arkret/self/device_messages")
            .send()
            .await?;
        if !response.status().is_success() {
            ensure!(
                matches!(
                    response.status(),
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                ),
                "old runtime failed for a non-authorization reason: {}",
                response.status()
            );
            let problem: arkret_wire::Problem = response.json().await?;
            println!(
                "[agent-repairing] superseded_session_status={} code={} freshness_max_seconds=60",
                problem.status,
                problem.code()
            );
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "superseded runtime session exceeded the 60s refusal window"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stale =
        pairing_expiry_evidence::replacement_material(station, &controller, &account, &agent)
            .await?;
    refused_supersedes(&controller, &database.connect_url, &stale.body, "stale").await?;
    lifecycle(&controller, &agent, "deactivate").await?;
    let before = acceptance_rows_with_agent_stores(&database.connect_url, true).await?;
    let response = controller
        .post(&format!(
            "/_arkret/self/agents/{}/renew-pairing",
            agent.agent_account.principal_id
        ))
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &AgentRenewPairingRequestBody {
                pairing_ttl_ms: Some(8000),
            },
        )?)
        .send()
        .await?;
    ensure!(
        !response.status().is_success(),
        "deactivated Agent renewed a handle"
    );
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        problem
            .extensions
            .get("reason_code")
            .and_then(Value::as_str)
            == Some(arkret_wire::ReasonCode::AGENT_DEACTIVATED),
        "deactivated renewal omitted its formal reason: {problem:?}"
    );
    ensure!(
        acceptance_rows_with_agent_stores(&database.connect_url, true).await? == before,
        "deactivated renewal changed full state"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: "agent_repairing_supersede".to_owned(),
            assertions: 8,
        }],
    })
}
