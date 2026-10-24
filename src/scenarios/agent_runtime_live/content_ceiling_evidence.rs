//! Actual provision/key ceilings and accepted runtime holder replacement.

use super::*;
use crate::harness::CanonicalJsonBody;

pub const REVIEWED_CEILING_CONTENT_CASES: [&str; 3] = [
    "provision_omits_content",
    "key_omits_content",
    "holder_authorization_replaced",
];

pub async fn run_agent_content_ceiling_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    let fixture = crate::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let contract = &fixture["session_content_authority_contract"];
    ensure!(
        arkret_canonical::sha256_hex(arkret_canonical::canonical_json_bytes(
            &contract["defaults"]
        )?) == "49fad7028393f37d28ca1a4ee06c376d6b16be0a16e4bfa35b77826a53130665"
    );
    for (name, input) in [
        ("provision_omits_content", json!({"provision_allows":false})),
        ("key_omits_content", json!({"key_allows":false})),
        (
            "holder_authorization_replaced",
            json!({"holder_current":false}),
        ),
    ] {
        let case = contract["cases"]
            .as_array()
            .context("content cases")?
            .iter()
            .find(|case| case["name"] == name)
            .context("ceiling case")?;
        ensure!(
            case["input"] == input && case["expected"] == "deny",
            "review changed ceiling obligation: {name}"
        );
    }
    let scene = content_grant_evidence::GrantFixture::establish().await?;
    let deployment = &scene.deployment;
    let station = &deployment.station;
    let controller = &deployment.controller;
    let agent = &scene.agent;
    let (before, claims) = scene.issue().await?;
    ensure!(claims.scopes.iter().any(|action| action == "ak.event.read"));
    scene.read_exact(&before).await?;
    let original = controller
        .sdk()
        .committed_event_get(&agent.key_authorization)
        .await?;
    let original = AgentKeyAuthorizePayload::try_from(
        original.reducer_input().context("accepted content key")?,
    )?;
    ensure!(
        original
            .agent_key_scope
            .actions
            .iter()
            .any(|action| action == "ak.event.read")
    );
    let mut service_scope = original.agent_key_scope.clone();
    service_scope
        .actions
        .retain(|action| ServiceOperationId::from_wire(action).is_some());
    ensure!(
        !service_scope
            .actions
            .iter()
            .any(|action| action == "ak.event.read")
    );
    let service_actions = service_scope
        .actions
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let replacement = pairing_expiry_evidence::replacement_material_with_scope(
        station,
        controller,
        &deployment.account,
        agent,
        60_000,
        Some(service_scope.clone()),
    )
    .await?;
    let paired: AgentKeyPairResponseBody = serde_json::from_value(
        expect_json(
            controller
                .authorize(station.http().post(format!(
                    "{}/_arkret/gate/account/agent-key-pair",
                    deployment.coauth.base_url()
                )))
                .header(
                    "Idempotency-Key",
                    replacement.body.authorize_event.event.event_id.as_str(),
                )
                .canonical_json(&replacement.body)?,
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
    coauth_session_evidence::wait_for_issuer_authorization(
        &deployment.coauth.pg.connect_url,
        &paired.authorize_event_ref,
    )
    .await?;
    let method = &replacement
        .bootstrap
        .validated_runtime_identity()
        .map_err(anyhow::Error::msg)?
        .verification_method;
    let view: arkret_models_collaboration::agent_operations::AgentView = serde_json::from_value(
        expect_json(
            controller.get(&format!(
                "/_arkret/self/agents/{}",
                agent.agent_account.principal_id
            )),
            StatusCode::OK,
        )
        .await?,
    )?;
    let dots = &view
        .key_state
        .as_ref()
        .context("current runtime key")?
        .active_authorizations;
    ensure!(
        view.key_state
            .as_ref()
            .context("immutable provision")?
            .requested_scope
            .actions
            .iter()
            .any(|action| action == "ak.event.read")
    );
    ensure!(
        dots.len() == 1
            && dots[0].authorized_event_ref == paired.authorize_event_ref
            && &dots[0].verification_method == method
    );
    let accepted = controller
        .sdk()
        .committed_event_get(&paired.authorize_event_ref)
        .await?;
    let accepted = AgentKeyAuthorizePayload::try_from(
        accepted.reducer_input().context("replacement original")?,
    )?;
    ensure!(
        serde_json::to_value(&accepted.agent_key_scope)? == serde_json::to_value(&service_scope)?
    );
    ensure!(
        accepted.supersedes.len() == 1
            && accepted.supersedes[0].authorized_event_ref == agent.key_authorization
    );
    let (credential, _) = coauth_session_evidence::issue_runtime_session(
        station,
        deployment.coauth.base_url(),
        &deployment.coauth.pg.connect_url,
        &agent.agent_account.principal_id,
        &paired.authorize_event_ref,
        method,
        &replacement.key,
        &service_actions,
    )
    .await?;
    let new_claims = content_session_evidence::observed_issued_claims(&credential)?;
    ensure!(
        !new_claims
            .scopes
            .iter()
            .any(|action| action == "ak.event.read")
    );
    let current = station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "current-service-holder",
        credential,
        replacement.key.clone(),
    )?;
    expect_json(current.get("/_arkret/self/device_messages"), StatusCode::OK).await?;
    let actions = scene
        .operations
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let issue_url = format!(
        "{}/_arkret/gate/account/session-grants",
        deployment.coauth.base_url()
    );
    let missing_key = coauth_session_evidence::build_runtime_session_request(
        station,
        deployment.coauth.base_url(),
        &agent.agent_account.principal_id,
        &paired.authorize_event_ref,
        method,
        &replacement.key,
        &actions,
        scene.selectors(),
    )?;
    coauth_session_evidence::expect_issue_refusal(
        station,
        &deployment.coauth.pg.connect_url,
        &issue_url,
        &missing_key,
        &replacement.key,
        None,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
        None,
    )
    .await?;
    let replaced_holder = coauth_session_evidence::build_runtime_session_request(
        station,
        deployment.coauth.base_url(),
        &agent.agent_account.principal_id,
        &agent.key_authorization,
        &agent.verification_method,
        &agent.runtime_key,
        &actions,
        scene.selectors(),
    )?;
    coauth_session_evidence::expect_issue_refusal(
        station,
        &deployment.coauth.pg.connect_url,
        &issue_url,
        &replaced_holder,
        &agent.runtime_key,
        None,
        arkret_wire::ErrorCode::SIGNATURE_INVALID,
        Some(arkret_wire::ReasonCode::PROOF_INVALID),
    )
    .await?;
    scene.read_exact(controller).await?;
    println!(
        "[agent-content-ceiling] accepted_content_key_positive=1 original_content_full=1 normal_pairing_supersedes_exact_dot=1 current_service_holder_works=1 key_missing_content_issue_denied=1 old_holder_fresh_issue_denied=1 no_op_issuer_ledger=1"
    );

    // A key cannot exceed immutable provision. The missing provision therefore also
    // bounds this second key; do not synthesize an impossible wider authorization.
    let second = AgentRuntimeSession::establish_observed(
        station,
        AgentSessionIssuer::Coauth {
            base: deployment.coauth.base_url(),
            database_url: &deployment.coauth.pg.connect_url,
        },
        controller,
        &deployment.account,
        "immutable-service-ceiling",
        service_scope.clone(),
        None,
    )
    .await?;
    let mut join = MembershipPayload::join(
        scene.realm.clone(),
        ActorId::account(second.agent_account.clone()),
        "immutable provision source control",
    );
    join.agent_controller_binding = Some(AgentControllerMembershipBinding {
        controller_account_id: deployment.account.clone(),
        controller_membership_generation_ref: scene.generation.clone(),
        controller_terminal_event_ref: None,
    });
    let joined: AuthoritySubmitResponseBody = serde_json::from_value(
        controller
            .submit_event(scene.realm.as_str(), "ak.member.state", join.to_value()?)
            .await?,
    )?;
    ensure!(matches!(
        joined,
        AuthoritySubmitResponseBody::Accepted {
            status: AuthorityCommitStatus::Committed,
            ..
        }
    ));
    let view: arkret_models_collaboration::agent_operations::AgentView = serde_json::from_value(
        expect_json(
            controller.get(&format!(
                "/_arkret/self/agents/{}",
                second.agent_account.principal_id
            )),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        serde_json::to_value(&view.key_state.context("service provision")?.requested_scope)?
            == serde_json::to_value(&service_scope)?
    );
    let fixture_source = controller
        .sdk()
        .committed_event_get(&scene.message.event_id)
        .await?;
    ensure!(matches!(
        fixture_source,
        arkret_wire::CommittedEventView::Full(_)
    ));
    let request = coauth_session_evidence::build_runtime_session_request(
        station,
        deployment.coauth.base_url(),
        &second.agent_account.principal_id,
        &second.key_authorization,
        &second.verification_method,
        &second.runtime_key,
        &actions,
        scene.selectors(),
    )?;
    coauth_session_evidence::expect_issue_refusal(
        station,
        &deployment.coauth.pg.connect_url,
        &issue_url,
        &request,
        &second.runtime_key,
        None,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
        None,
    )
    .await?;
    expect_json(
        second.runtime.get("/_arkret/self/device_messages"),
        StatusCode::OK,
    )
    .await?;
    println!(
        "[agent-content-ceiling] immutable_service_provision=1 valid_service_session=1 content_issue_denied=1 key_cannot_exceed_provision=1"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: REVIEWED_CEILING_CONTENT_CASES
            .iter()
            .map(|name| crate::conformance::CaseExecutionResult {
                case_id: (*name).to_owned(),
                assertions: 1,
            })
            .collect(),
    })
}
