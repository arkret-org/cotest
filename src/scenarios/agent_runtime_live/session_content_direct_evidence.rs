//! Real Coauth issuance from an accepted owned Direct participant source.

use super::*;
use crate::harness::CanonicalJsonBody;

pub async fn run_agent_direct_content_session_boundary() -> Result<()> {
    let deployment =
        coauth_session_evidence::actual_agent_deployment("agent-direct-content").await?;
    let station = &deployment.station;
    let controller = &deployment.controller;
    let mut actions = runtime_operations().to_vec();
    actions.extend([
        ServiceOperationId::SELF_COMMITTED_EVENT_RESOURCE_GET_V1,
        "ak.event.read",
        "ak.message.create",
    ]);
    let completed = arkret_schema::agent_runtime_scope::complete_agent_runtime_scope(actions)?;
    let actions = completed.iter().map(String::as_str).collect::<Vec<_>>();
    let agent = AgentRuntimeSession::establish_observed(
        station,
        AgentSessionIssuer::Coauth {
            base: deployment.coauth.base_url(),
            database_url: &deployment.coauth.pg.connect_url,
        },
        controller,
        &deployment.account,
        "direct-content-agent",
        requested_scope(&actions)?,
        None,
    )
    .await?;
    let prior =
        content_session_evidence::observed_issued_claims(agent.runtime.session().credential())?;
    ensure!(!prior.scopes.iter().any(|action| action == "ak.event.read"));
    let founded = direct_evidence::found(controller, &agent, station).await?;
    let realm = founded.coordinates.realm_id.clone();
    let page = controller
        .sdk()
        .scan_commit_stream(&arkret_wire::StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            direction: arkret_wire::StreamScanDirection::After(None),
            limit: 20,
        })
        .await?;
    let content = page
        .committed_events
        .iter()
        .filter_map(|row| row.reducer_input())
        .find(|event| event.kind == arkret_wire::EventKind::StrandCreate)
        .context("accepted Direct Strand after both participant joins")?;
    let path = format!("/_arkret/self/committed-events/{}", content.event_id);
    require_content_refusal(
        agent.runtime.get(&path).send().await?,
        "direct_predecessor",
        false,
    )
    .await?;
    let (credential, issued) = coauth_session_evidence::issue_runtime_session_with_scope(
        station,
        deployment.coauth.base_url(),
        &deployment.coauth.pg.connect_url,
        &agent.agent_account.principal_id,
        &agent.key_authorization,
        &agent.verification_method,
        &agent.runtime_key,
        &actions,
        arkret_models_collaboration::session_grants::SessionGrantAgentScopeRequest {
            realm_ids: vec![realm],
            strand_ids: Vec::new(),
            track_names: Vec::new(),
        },
    )
    .await?;
    let current = content_session_evidence::observed_issued_claims(&credential)?;
    ensure!(current.session_id != prior.session_id);
    ensure!(
        current
            .scopes
            .iter()
            .any(|action| action == "ak.event.read")
    );
    ensure!(
        !current
            .scopes
            .iter()
            .any(|action| action == "ak.message.create"),
        "provisional Direct read manufactured a participant write source"
    );
    ensure!(
        current
            .scope_details
            .as_ref()
            .context("Direct content ceiling")?["capability_grant_refs"]
            == json!([])
    );
    let runtime = station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "direct-content-reader",
        credential,
        agent.runtime_key.clone(),
    )?;
    let disclosed: arkret_wire::CommittedEventView =
        serde_json::from_value(expect_json(runtime.get(&path), StatusCode::OK).await?)?;
    ensure!(
        matches!(disclosed, arkret_wire::CommittedEventView::Full(ref full) if full.event == *content)
    );
    let refresh_url = format!(
        "{}/_arkret/gate/account/session-grants/refresh",
        deployment.coauth.base_url()
    );
    let refresh = content_session_evidence::content_refresh_request(
        station,
        &agent,
        runtime.session().credential(),
    )?;
    let refreshed = runtime
        .authorize(station.http().post(&refresh_url))
        .canonical_json(&refresh)?
        .send()
        .await?;
    ensure!(refreshed.status().is_success());
    let refreshed: arkret_models_collaboration::session_grants::SessionGrantOutcome =
        refreshed.json().await?;
    let claims = content_session_evidence::observed_issued_claims(&refreshed.session_grant)?;
    ensure!(
        claims.session_id == current.session_id
            && claims.scopes == current.scopes
            && claims.scope_details == current.scope_details
    );
    let runtime = station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "direct-content-refreshed",
        refreshed.session_grant,
        agent.runtime_key.clone(),
    )?;
    expect_json(runtime.get(&path), StatusCode::OK).await?;
    agent
        .transition(controller, &deployment.account, AgentTransition::Pause)
        .await?;
    require_content_refusal(
        runtime.get(&path).send().await?,
        "direct_paused_read",
        false,
    )
    .await?;
    let ledger = coauth_session_evidence::grant_ledger(&deployment.coauth.pg.connect_url).await?;
    let refresh = content_session_evidence::content_refresh_request(
        station,
        &agent,
        runtime.session().credential(),
    )?;
    let refused = runtime
        .authorize(station.http().post(&refresh_url))
        .canonical_json(&refresh)?
        .send()
        .await?;
    require_content_refusal(refused, "direct_paused_refresh", true).await?;
    let issue_url = format!(
        "{}/_arkret/gate/account/session-grants",
        deployment.coauth.base_url()
    );
    let request =
        coauth_session_evidence::fresh_session_request(&issued, &issue_url, &agent.runtime_key)?;
    let proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new("POST", &issue_url),
        &agent.runtime_key,
    )?;
    let refused = station
        .http()
        .post(&issue_url)
        .header("DPoP", proof.proof_jwt)
        .canonical_json(&request)?
        .send()
        .await?;
    require_content_refusal(refused, "direct_paused_issue", true).await?;
    ensure!(
        ledger == coauth_session_evidence::grant_ledger(&deployment.coauth.pg.connect_url).await?
    );
    ensure!(
        prior.expires_at > Utc::now() && claims.expires_at > Utc::now(),
        "Direct lifecycle test reached natural credential expiry"
    );
    println!(
        "[agent-direct-content] real_coauth=1 accepted_founding=1 fresh_issue=1 no_literal_grant=1 actual_read=1 provisional_read_not_write=1 pause_closes_read_and_issue=1 refused_issue_ledger_unchanged=1"
    );
    Ok(())
}

async fn require_content_refusal(
    response: reqwest::Response,
    boundary: &str,
    issuer: bool,
) -> Result<()> {
    let status = response.status();
    if status.is_success() {
        let shape = if issuer {
            "issuer_success"
        } else {
            match response.json::<arkret_wire::CommittedEventView>().await? {
                arkret_wire::CommittedEventView::Full(_) => "full_event",
                arkret_wire::CommittedEventView::Withheld(_) => "withheld_event",
            }
        };
        anyhow::bail!(
            "unexpected successful content response at {boundary}: {status} shape={shape}"
        );
    }
    let problem: arkret_wire::Problem = response.json().await?;
    use arkret_wire::ErrorCode as Code;
    let current = [
        (StatusCode::UNAUTHORIZED, Code::UNAUTHENTICATED),
        (StatusCode::UNAUTHORIZED, Code::AUTH_EXPIRED),
        (StatusCode::FORBIDDEN, Code::CAPABILITY_DENIED),
        (StatusCode::FORBIDDEN, Code::FAILED_PRECONDITION),
        (StatusCode::FORBIDDEN, Code::POLICY_VIOLATION),
        (StatusCode::NOT_FOUND, Code::NOT_FOUND),
    ];
    ensure!(
        current.contains(&(status, problem.code()))
            || (issuer
                && status == StatusCode::SERVICE_UNAVAILABLE
                && problem.code() == Code::POLICY_UNAVAILABLE),
        "unexpected content refusal at {boundary}: {status} {}",
        problem.code()
    );
    println!(
        "[agent-content-refusal] boundary={boundary} status={} code={}",
        status.as_u16(),
        problem.code()
    );
    Ok(())
}
