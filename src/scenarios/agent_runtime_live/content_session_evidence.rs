//! Real content-session issuance, immutable refresh and current read boundaries.

use super::*;
use crate::harness::CanonicalJsonBody;

fn observed_issued_claims(
    credential: &str,
) -> Result<arkret_models_identity::SignedSessionGrantClaims> {
    // This is a test observation; the real Station independently verifies
    // issuer signature, introspection and holder binding before every read.
    let payload = credential
        .split('.')
        .nth(1)
        .context("issuer credential payload")?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?)
}

fn content_refresh_request(
    station: &crate::harness::ArkretServer,
    agent: &AgentRuntimeSession,
    credential: &str,
) -> Result<arkret_models_collaboration::session_grants::SessionGrantRefreshRequestBody> {
    use arkret_models_collaboration::session_grant_bodies::{
        AgentSessionGrantRefreshRequest, AgentSessionRefreshProofContext,
        UnsignedAgentSessionRefreshProof,
    };
    use ed25519_dalek::Signer as _;
    let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let unsigned = UnsignedAgentSessionRefreshProof {
        context: AgentSessionRefreshProofContext::V1,
        request_canonical_digest:
            arkret_models_collaboration::session_grant_bodies::agent_session_refresh_request_digest(
                credential,
                &agent.agent_account.principal_id,
                &agent.key_authorization,
                station.service_id(),
                &agent.verification_method,
            )?,
        audience_id: station.service_id().clone(),
        issued_at: now,
        expires_at: now + chrono::Duration::minutes(1),
        verification_method: agent.verification_method.clone(),
    };
    let signature = agent.runtime_key.sign(&unsigned.canonical_signing_bytes()?);
    Ok(
        arkret_models_collaboration::session_grants::SessionGrantRefreshRequestBody::Agent(
            AgentSessionGrantRefreshRequest {
                grant_jwt: credential.to_owned(),
                audience_id: Some(station.service_id().clone()),
                principal_id: agent.agent_account.principal_id.clone(),
                agent_key_authorization_ref: agent.key_authorization.clone(),
                agent_session_refresh_proof: unsigned.attach_signature(
                    arkret_wire::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
                        .map_err(anyhow::Error::msg)?,
                )?,
            },
        ),
    )
}

/// Actual issuer/Station boundary for membership-derived content sessions.
/// This has no fixture introspection and creates no literal read or write grant.
pub async fn run_agent_session_content_read_boundary() -> Result<()> {
    run_agent_session_content_production().await.map(|_| ())
}

pub const REVIEWED_CONTENT_CASES: [&str; 10] = [
    "membership_read_without_literal_grant",
    "no_policy_with_complete_current_evidence",
    "membership_does_not_grant_write",
    "fresh_issue_after_service_session",
    "refresh_preserves_existing_ceiling",
    "refresh_rejects_scope_expansion",
    "refresh_rejects_scope_request_field",
    "refresh_current_authority_lost",
    "ordinary_controller_read_revoked",
    "session_service_only_cannot_read",
];

pub async fn run_agent_session_content_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    let fixture = crate::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let contract = &fixture["session_content_authority_contract"];
    ensure!(
        arkret_canonical::sha256_hex(arkret_canonical::canonical_json_bytes(
            &contract["defaults"]
        )?) == "49fad7028393f37d28ca1a4ee06c376d6b16be0a16e4bfa35b77826a53130665",
        "review the changed content-authority baseline before crediting live evidence"
    );
    let declared = contract["cases"]
        .as_array()
        .context("content authority cases")?;
    for name in REVIEWED_CONTENT_CASES {
        ensure!(
            declared.iter().filter(|case| case["name"] == name).count() == 1,
            "reviewed content case is not uniquely declared: {name}"
        );
    }
    for (name, input, expected) in [
        ("membership_read_without_literal_grant", json!({}), "allow"),
        (
            "no_policy_with_complete_current_evidence",
            json!({}),
            "allow",
        ),
        (
            "membership_does_not_grant_write",
            json!({"action":"ak.message.create"}),
            "deny",
        ),
        (
            "fresh_issue_after_service_session",
            json!({"session_allows":false,"predecessor_has_content":false}),
            "allow",
        ),
        (
            "refresh_preserves_existing_ceiling",
            json!({"phase":"refresh"}),
            "allow",
        ),
        (
            "refresh_rejects_scope_expansion",
            json!({"phase":"refresh","refresh_ceiling_unchanged":false}),
            "deny",
        ),
        (
            "refresh_rejects_scope_request_field",
            json!({"phase":"refresh","scope_request_field_present":true}),
            "deny",
        ),
        (
            "refresh_current_authority_lost",
            json!({"phase":"refresh","source_current":false}),
            "deny",
        ),
        (
            "ordinary_controller_read_revoked",
            json!({"controller_allows":false}),
            "deny",
        ),
        (
            "session_service_only_cannot_read",
            json!({"phase":"payload","session_allows":false}),
            "deny",
        ),
    ] {
        let case = declared
            .iter()
            .find(|case| case["name"] == name)
            .context("reviewed content case")?;
        ensure!(
            case["input"] == input && case["expected"] == expected,
            "review the changed real content obligation: {name}"
        );
    }
    let deployment = coauth_session_evidence::actual_agent_deployment("agent-content-read").await?;
    let station = &deployment.station;
    let controller = &deployment.controller;
    let created = controller
        .create_realm_with(json!({
            "title":"Membership content session", "public":false, "join_rule":"public",
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
            .and_then(|rows| rows.last())
            .and_then(|row| row["event_ref"].as_str())
            .context("controller membership generation")?,
    )?;
    let mut actions = runtime_operations().to_vec();
    actions.extend([
        ServiceOperationId::SELF_COMMITTED_EVENT_RESOURCE_GET_V1,
        "ak.event.read",
        "ak.message.create",
    ]);
    let completed = arkret_schema::agent_runtime_scope::complete_agent_runtime_scope(actions)?;
    let actions = completed.iter().map(String::as_str).collect::<Vec<_>>();
    let mut scope = requested_scope(&actions)?;
    scope.resources.push(serde_json::from_value(
        json!({"kind":"strand","realm_id":realm,"resource_ref":strand}),
    )?);
    let issuer = AgentSessionIssuer::Coauth {
        base: deployment.coauth.base_url(),
        database_url: &deployment.coauth.pg.connect_url,
    };
    let agent = AgentRuntimeSession::establish_observed(
        station,
        issuer,
        controller,
        &deployment.account,
        "membership-content-agent",
        scope,
        None,
    )
    .await?;
    let old_credential = agent.runtime.session().credential().to_owned();
    let old = observed_issued_claims(&old_credential)?;
    ensure!(!old.scopes.iter().any(|action| action == "ak.event.read"));
    let mut joined = MembershipPayload::join(
        realm.clone(),
        ActorId::account(agent.agent_account.clone()),
        "exact owned member read source",
    );
    joined.agent_controller_binding = Some(AgentControllerMembershipBinding {
        controller_account_id: deployment.account.clone(),
        controller_membership_generation_ref: generation,
        controller_terminal_event_ref: None,
    });
    let joined = controller
        .author_event(realm.as_str(), "ak.member.state", joined.to_value()?)
        .await?;
    expect_json(
        controller
            .post("/_arkret/self/events")
            .canonical_json(&arkret_wire::EventAdmissionSubmission::new(joined.clone()))?,
        StatusCode::OK,
    )
    .await?;
    let content = controller.author_event(realm.as_str(), "ak.message.create", json!({
        "strand_id":strand,"track_name":"discussion",
        "content":{"kind":"ak.content.text","body":"Membership-derived read after the exact join"}
    })).await?;
    expect_json(
        controller
            .post("/_arkret/self/events")
            .canonical_json(&arkret_wire::EventAdmissionSubmission::new(content.clone()))?,
        StatusCode::OK,
    )
    .await?;
    let path = format!("/_arkret/self/committed-events/{}", content.event_id);
    let previous = agent.runtime.get(&path).send().await?;
    let status = previous.status();
    let problem: arkret_wire::Problem = previous.json().await?;
    ensure!(
        status == StatusCode::FORBIDDEN && problem.code() == "capability_denied",
        "service-only read failed at the wrong boundary: {status} {problem:?}"
    );
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
            realm_ids: Vec::new(),
            strand_ids: vec![strand],
            track_names: Vec::new(),
        },
    )
    .await?;
    let ledger = coauth_session_evidence::grant_ledger(&deployment.coauth.pg.connect_url).await?;
    let old_rows = ledger
        .as_array()
        .context("issuer grant rows")?
        .iter()
        .filter(|row| row["grant_jwt"] == old_credential)
        .collect::<Vec<_>>();
    ensure!(
        old_rows.len() == 1
            && old_rows[0]["lifecycle_state"] == "active"
            && old_rows[0]["successor_grant_id"].is_null(),
        "fresh issuance superseded or revoked the predecessor grant"
    );
    let fresh = observed_issued_claims(&credential)?;
    ensure!(fresh.scopes.iter().any(|action| action == "ak.event.read"));
    ensure!(
        !fresh
            .scopes
            .iter()
            .any(|action| action == "ak.message.create"),
        "membership read created write authority"
    );
    ensure!(
        fresh.session_id != old.session_id,
        "fresh issue superseded its independent predecessor chain"
    );
    let details = fresh
        .scope_details
        .as_ref()
        .context("content scope details")?;
    ensure!(details["capability_grant_refs"] == json!([]) && details["policy_refs"] == json!([]));
    let runtime = station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "membership-content-runtime",
        credential.clone(),
        agent.runtime_key.clone(),
    )?;
    let disclosed: arkret_wire::CommittedEventView =
        expect_json(runtime.get(&path), StatusCode::OK)
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?;
    ensure!(
        matches!(disclosed, arkret_wire::CommittedEventView::Full(ref full) if full.event == content)
    );
    ensure!(
        observed_issued_claims(&old_credential)?.scopes == old.scopes,
        "new issue mutated old credential"
    );
    let refresh_url = format!(
        "{}/_arkret/gate/account/session-grants/refresh",
        deployment.coauth.base_url()
    );
    // Refresh has a closed request shape: neither a new scope nor resource
    // selectors may change the already-issued ceiling.
    for (field, value) in [
        ("scope", json!(["ak.event.read", "ak.message.create"])),
        (
            "agent_scope_request",
            json!({"realm_ids":[realm], "strand_ids":[], "track_names":[]}),
        ),
    ] {
        let before =
            coauth_session_evidence::issuer_state(&deployment.coauth.pg.connect_url).await?;
        let mut body =
            serde_json::to_value(content_refresh_request(station, &agent, &credential)?)?;
        body.as_object_mut()
            .context("refresh object")?
            .insert(field.into(), value);
        let response = runtime
            .authorize(station.http().post(&refresh_url))
            .canonical_json(&body)?
            .send()
            .await?;
        let status = response.status();
        let problem: arkret_wire::Problem = response.json().await?;
        ensure!(
            status == StatusCode::BAD_REQUEST && problem.code() == "json_invalid",
            "refresh accepted an expanded request or refused at the wrong boundary: {field} {status} {problem:?}"
        );
        ensure!(
            before
                == coauth_session_evidence::issuer_state(&deployment.coauth.pg.connect_url).await?,
            "invalid refresh changed issuer state"
        );
    }
    let refresh = content_refresh_request(station, &agent, &credential)?;
    let response = runtime
        .authorize(station.http().post(&refresh_url))
        .canonical_json(&refresh)?
        .send()
        .await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    ensure!(
        status.is_success(),
        "current content refresh refused: {status} {}",
        String::from_utf8_lossy(&bytes)
    );
    let rotated: arkret_models_collaboration::session_grants::SessionGrantOutcome =
        serde_json::from_slice(&bytes)?;
    let next = observed_issued_claims(&rotated.session_grant)?;
    ensure!(
        next.scopes == fresh.scopes
            && next.scope_details == fresh.scope_details
            && next.session_id == fresh.session_id,
        "refresh expanded or changed the immutable content ceiling"
    );
    let rotated_runtime = station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "membership-content-rotated",
        rotated.session_grant.clone(),
        agent.runtime_key.clone(),
    )?;
    expect_json(rotated_runtime.get(&path), StatusCode::OK).await?;
    controller
        .submit_event(
            realm.as_str(),
            "ak.member.state",
            json!({"member_id":ActorId::account(deployment.account.clone()),"membership":"leave"}),
        )
        .await?;
    let denied = rotated_runtime.get(&path).send().await?;
    let status = denied.status();
    let problem: arkret_wire::Problem = denied.json().await?;
    ensure!(
        status == StatusCode::FORBIDDEN && problem.code() == "capability_denied",
        "withdrawn content read failed at the wrong boundary: {status} {problem:?}"
    );
    let ledger = coauth_session_evidence::issuer_state(&deployment.coauth.pg.connect_url).await?;
    let refresh = content_refresh_request(station, &agent, &rotated.session_grant)?;
    let denied = rotated_runtime
        .authorize(station.http().post(&refresh_url))
        .canonical_json(&refresh)?
        .send()
        .await?;
    let status = denied.status();
    let problem: arkret_wire::Problem = denied.json().await?;
    ensure!(
        status == StatusCode::FORBIDDEN && problem.code() == "capability_denied",
        "refresh restored a withdrawn content source: {status} {problem:?}"
    );
    ensure!(
        ledger == coauth_session_evidence::issuer_state(&deployment.coauth.pg.connect_url).await?
    );
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
    let denied = station
        .http()
        .post(&issue_url)
        .header("DPoP", proof.proof_jwt)
        .canonical_json(&request)?
        .send()
        .await?;
    let status = denied.status();
    let problem: arkret_wire::Problem = denied.json().await?;
    ensure!(
        status == StatusCode::FORBIDDEN && problem.code() == "capability_denied",
        "fresh issuance restored a withdrawn content source: {status} {problem:?}"
    );
    ensure!(
        ledger == coauth_session_evidence::issuer_state(&deployment.coauth.pg.connect_url).await?
    );
    println!(
        "[agent-content-session] real_issuer=1 service_only_predecessor=1 membership_read_without_literal_grant=1 fresh_issue_independent_chain=1 no_read_to_write=1 actual_station_read=1 unchanged_refresh_ceiling=1 current_withdrawal_blocks_read_issue_refresh=1"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: REVIEWED_CONTENT_CASES
            .into_iter()
            .map(|name| crate::conformance::CaseExecutionResult {
                case_id: name.to_owned(),
                assertions: 1,
            })
            .collect(),
    })
}
