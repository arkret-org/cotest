//! Real content-session issuance, immutable refresh and current read boundaries.

use super::*;
use crate::harness::CanonicalJsonBody;

pub(super) fn observed_issued_claims(
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

pub(super) fn content_refresh_request(
    station: &crate::harness::ArkretServer,
    agent: &AgentRuntimeSession,
    credential: &str,
) -> Result<arkret_models_collaboration::session_grants::SessionGrantRefreshRequestBody> {
    use arkret_models_collaboration::session_grant_bodies::{
        AgentSessionGrantRefreshRequestBody, AgentSessionRefreshProofContext,
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
            AgentSessionGrantRefreshRequestBody {
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

pub const REVIEWED_CONTENT_CASES: [&str; 20] = [
    "membership_read_without_literal_grant",
    "membership_does_not_grant_write",
    "provision_only_is_not_authority",
    "participation_only_is_not_authority",
    "accountability_only_is_not_authority",
    "fresh_issue_after_service_session",
    "refresh_preserves_existing_ceiling",
    "refresh_rejects_scope_expansion",
    "refresh_rejects_scope_request_field",
    "refresh_current_authority_lost",
    "exact_issue_replay_unchanged",
    "terminal_issue_replay",
    "conflicting_issue_replay",
    "no_policy_with_complete_current_evidence",
    "request_omits_content",
    "content_selector_missing",
    "runtime_mandatory_floor_missing",
    "issuer_proof_invalid",
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
        (
            "participation_only_is_not_authority",
            json!({"paths":[{"kind":"participation","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":true}]}),
            "deny",
        ),
        (
            "accountability_only_is_not_authority",
            json!({"paths":[{"kind":"accountability","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":true}]}),
            "deny",
        ),
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
        ("issuer_proof_invalid", json!({"proof_valid":false}), "deny"),
        (
            "conflicting_issue_replay",
            json!({"replay_state":"conflict"}),
            "deny",
        ),
        (
            "exact_issue_replay_unchanged",
            json!({"replay_state":"active_exact","source_current":false}),
            "reuse_original",
        ),
        (
            "terminal_issue_replay",
            json!({"replay_state":"terminal_exact"}),
            "deny",
        ),
        (
            "provision_only_is_not_authority",
            json!({"paths":[]}),
            "deny",
        ),
        (
            "request_omits_content",
            json!({"request_allows":false}),
            "deny",
        ),
        (
            "content_selector_missing",
            json!({"content_selector_present":false}),
            "deny",
        ),
        (
            "runtime_mandatory_floor_missing",
            json!({"runtime_floor_complete":false}),
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
        // This accepted immutable selection activates the registry's chat floor.
        ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
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
    let issue_url = format!(
        "{}/_arkret/gate/account/session-grants",
        deployment.coauth.base_url()
    );
    let content_scope =
        || arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope {
            realm_ids: Vec::new(),
            strand_ids: vec![strand.clone()],
            track_names: Vec::new(),
        };
    let accountability_source = coauth_session_evidence::set_accountability_with_source(
        controller,
        &agent.agent_account.principal_id,
        &deployment.account,
        arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus::Active,
    )
    .await?;
    let accountability: arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload =
        serde_json::from_value(serde_json::to_value(
            &accountability_source.reducer_input().context("accepted accountability original")?.payload
        )?)?;
    ensure!(accountability.accountability_scope.canonical_set()?
        == vec![arkret_models_collaboration::governance::accountability::AccountabilityScopeKind::AgentOperator]);
    ensure!(accountability.issuer_id == deployment.account.principal_id
        && accountability.subject_id == agent.agent_account.principal_id
        && accountability.grant_status == arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus::Active
        && accountability.not_before <= Utc::now()
        && accountability.expires_at.is_none_or(|expiry|expiry>Utc::now()));
    let prejoin = coauth_session_evidence::build_runtime_session_request(
        station,
        deployment.coauth.base_url(),
        &agent.agent_account.principal_id,
        &agent.key_authorization,
        &agent.verification_method,
        &agent.runtime_key,
        &actions,
        content_scope(),
    )?;
    coauth_session_evidence::expect_issue_refusal(
        station,
        &deployment.coauth.pg.connect_url,
        &issue_url,
        &prejoin,
        &agent.runtime_key,
        None,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
        None,
    )
    .await?;
    let selection = arkret::ParticipationReplaceRequestBody {
        target_scope: arkret::ParticipationScope::Realm {
            realm_id: realm.clone(),
        },
        selection: arkret::ParticipationBits {
            message_creation_allowed: true,
            ..arkret::ParticipationBits::NONE
        },
        expected_version: 0,
    };
    let selected = controller
        .sdk()
        .agent_participation_replace(agent.agent_account.principal_id.as_str(), &selection)
        .await?;
    ensure!(selected.participation_entries.len() == 1);
    let entry = &selected.participation_entries[0];
    ensure!(
        entry.target_scope == selection.target_scope
            && entry.selection.message_creation_allowed
            && entry.version == 1
    );
    let with_selection = coauth_session_evidence::build_runtime_session_request(
        station,
        deployment.coauth.base_url(),
        &agent.agent_account.principal_id,
        &agent.key_authorization,
        &agent.verification_method,
        &agent.runtime_key,
        &actions,
        content_scope(),
    )?;
    coauth_session_evidence::expect_issue_refusal(
        station,
        &deployment.coauth.pg.connect_url,
        &issue_url,
        &with_selection,
        &agent.runtime_key,
        None,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
        None,
    )
    .await?;
    let retained = controller
        .sdk()
        .agent_participation_get(agent.agent_account.principal_id.as_str())
        .await?;
    ensure!(serde_json::to_value(&retained)? == serde_json::to_value(&selected)?);
    expect_json(
        agent.runtime.get("/_arkret/self/device_messages"),
        StatusCode::OK,
    )
    .await?;
    println!(
        "[agent-non-authority] accepted_active_accountability_current=1 actual_service_holder_valid=1 no_realm_join_or_content_source=1 fresh_content_issue_denied=1 normal_reply_selection_saved=1 selection_current_retained=1 selection_does_not_create_read_authority=1 full_issuer_state_unchanged=1"
    );
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
        arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope {
            realm_ids: Vec::new(),
            strand_ids: vec![strand.clone()],
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
    ensure!(
        arkret_schema::agent_runtime_scope::assess_agent_runtime_scopes(
            &completed,
            &completed,
            &fresh.scopes,
        )?
        .is_none(),
        "successful content issue omitted its selected runtime floor"
    );
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
    let service_actions = actions
        .iter()
        .copied()
        .filter(|action| ServiceOperationId::from_wire(action).is_some())
        .collect::<Vec<_>>();
    for (label, requested, selectors) in [
        (
            "request_omits_content",
            service_actions.as_slice(),
            content_scope(),
        ),
        (
            "content_selector_missing",
            actions.as_slice(),
            arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope {
                realm_ids: Vec::new(),
                strand_ids: Vec::new(),
                track_names: Vec::new(),
            },
        ),
    ] {
        let (bounded, _) = coauth_session_evidence::issue_runtime_session_with_scope(
            station,
            deployment.coauth.base_url(),
            &deployment.coauth.pg.connect_url,
            &agent.agent_account.principal_id,
            &agent.key_authorization,
            &agent.verification_method,
            &agent.runtime_key,
            requested,
            selectors,
        )
        .await?;
        ensure!(
            !observed_issued_claims(&bounded)?
                .scopes
                .iter()
                .any(|scope| scope == "ak.event.read"),
            "{label} unexpectedly obtained content authority"
        );
        let bounded_runtime = station.client_with_agent_runtime_grant(
            agent.agent_did.as_str(),
            label,
            bounded,
            agent.runtime_key.clone(),
        )?;
        let response = bounded_runtime.get(&path).send().await?;
        let status = response.status();
        let problem: arkret_wire::Problem = response.json().await?;
        ensure!(
            status == StatusCode::FORBIDDEN && problem.code() == "capability_denied",
            "{label} reached the wrong content boundary: {status} {problem:?}"
        );
    }
    let mut incomplete =
        coauth_session_evidence::fresh_session_request(&issued, &issue_url, &agent.runtime_key)?;
    incomplete
        .requested_scope
        .retain(|scope| scope != ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1);
    let deficiency = arkret_schema::agent_runtime_scope::assess_agent_runtime_scopes(
        &completed,
        &completed,
        &incomplete.requested_scope,
    )?
    .context("test request must actually omit a selected mandatory runtime operation")?;
    ensure!(
        deficiency.layer == arkret_schema::agent_runtime_scope::AgentRuntimeScopeLayer::Session
            && deficiency.missing_operations
                == vec![ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1.to_owned()],
        "runtime-floor rejection test has the wrong verified premise: {deficiency:?}"
    );
    resign_issue(&mut incomplete, &agent.runtime_key)?;
    coauth_session_evidence::expect_issue_refusal(
        station,
        &deployment.coauth.pg.connect_url,
        &issue_url,
        &incomplete,
        &agent.runtime_key,
        None,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
        Some(arkret_wire::ReasonCode::AGENT_SESSION_SCOPE_REFRESH_REQUIRED),
    )
    .await?;
    let (parallel_credential, parallel_request) =
        coauth_session_evidence::issue_runtime_session_with_scope(
            station,
            deployment.coauth.base_url(),
            &deployment.coauth.pg.connect_url,
            &agent.agent_account.principal_id,
            &agent.key_authorization,
            &agent.verification_method,
            &agent.runtime_key,
            &actions,
            content_scope(),
        )
        .await?;
    let (status, original_parallel) =
        send_issue(station, &issue_url, &parallel_request, &agent.runtime_key).await?;
    ensure!(
        status == StatusCode::OK,
        "active issue replay was refused before source withdrawal"
    );
    let original_outcome: arkret_models_collaboration::session_grants::SessionGrantResponseBody =
        serde_json::from_slice(&original_parallel)?;
    ensure!(original_outcome.session_grant == parallel_credential);
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
    let rotated: arkret_models_collaboration::session_grants::SessionGrantResponseBody =
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
    coauth_session_evidence::expect_issue_refusal(
        station,
        &deployment.coauth.pg.connect_url,
        &issue_url,
        &issued,
        &agent.runtime_key,
        None,
        arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_TERMINAL,
        None,
    )
    .await?;
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
    let before_replay =
        coauth_session_evidence::issuer_state(&deployment.coauth.pg.connect_url).await?;
    let (status, replayed) =
        send_issue(station, &issue_url, &parallel_request, &agent.runtime_key).await?;
    ensure!(
        status == StatusCode::OK && replayed == original_parallel,
        "exact completed issue replay changed after its Realm source was withdrawn: {status}"
    );
    ensure!(
        before_replay
            == coauth_session_evidence::issuer_state(&deployment.coauth.pg.connect_url).await?
    );
    let parallel_runtime = station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "parallel-after-withdrawal",
        parallel_credential,
        agent.runtime_key.clone(),
    )?;
    let response = parallel_runtime.get(&path).send().await?;
    let status = response.status();
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        status == StatusCode::FORBIDDEN && problem.code() == "capability_denied",
        "retained issue outcome restored withdrawn payload authority: {status} {problem:?}"
    );
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
    ensure!(
        Utc::now() < fresh.expires_at && Utc::now() < next.expires_at,
        "current withdrawal must refuse before either content credential naturally expires"
    );
    println!(
        "[agent-content-session] real_issuer=1 service_only_predecessor=1 membership_read_without_literal_grant=1 fresh_issue_independent_chain=1 no_read_to_write=1 actual_station_read=1 unchanged_refresh_ceiling=1 current_withdrawal_blocks_read_issue_refresh=1"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: declared
            .iter()
            .filter_map(|case| {
                let name = case["name"].as_str()?;
                REVIEWED_CONTENT_CASES.contains(&name).then(|| {
                    crate::conformance::CaseExecutionResult {
                        case_id: name.to_owned(),
                        assertions: 1,
                    }
                })
            })
            .collect(),
    })
}

fn resign_issue(
    request: &mut arkret_models_collaboration::session_grants::AgentSessionGrantRequestBody,
    key: &ed25519_dalek::SigningKey,
) -> Result<()> {
    use ed25519_dalek::Signer as _;
    request.proof.request_canonical_digest = request.canonical_request_digest()?;
    request.proof.signature = URL_SAFE_NO_PAD.encode(
        key.sign(&request.proof.canonical_signing_bytes()?)
            .to_bytes(),
    );
    request.validate()?;
    Ok(())
}

async fn send_issue(
    station: &ArkretServer,
    url: &str,
    request: &arkret_models_collaboration::session_grants::AgentSessionGrantRequestBody,
    key: &ed25519_dalek::SigningKey,
) -> Result<(StatusCode, Vec<u8>)> {
    let proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new("POST", url),
        key,
    )?;
    let response = station
        .http()
        .post(url)
        .header("DPoP", proof.proof_jwt)
        .canonical_json(request)?
        .send()
        .await?;
    Ok((response.status(), response.bytes().await?.to_vec()))
}
