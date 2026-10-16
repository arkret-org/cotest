//! Real Agent pairing failure classifications on accepted controller authority.
use arkret_models_collaboration::agent_operations::{
    AgentRenewPairingOutcome, AgentRenewPairingRequestBody,
};
use arkret_models_collaboration::agent_scope::AgentKeyPairRequestBody;

use super::*;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

async fn replacement(
    station: &ArkretServer,
    controller: &TestActorClient,
    account: &AccountId,
    agent: &AgentRuntimeSession,
) -> Result<(AgentKeyPairRequestBody, chrono::DateTime<Utc>)> {
    let material = replacement_material(station, controller, account, agent).await?;
    Ok((material.body, material.bootstrap.pairing_expires_at))
}

pub(super) struct ReplacementMaterial {
    pub(super) body: AgentKeyPairRequestBody,
    pub(super) bootstrap: AgentPairingBootstrap,
    pub(super) key: SigningKey,
}

pub(super) async fn replacement_material(
    station: &ArkretServer,
    controller: &TestActorClient,
    account: &AccountId,
    agent: &AgentRuntimeSession,
) -> Result<ReplacementMaterial> {
    replacement_material_with_ttl(station, controller, account, agent, 8000).await
}

pub(super) async fn replacement_material_with_ttl(
    station: &ArkretServer,
    controller: &TestActorClient,
    account: &AccountId,
    agent: &AgentRuntimeSession,
    pairing_ttl_ms: u64,
) -> Result<ReplacementMaterial> {
    replacement_material_with_scope(station, controller, account, agent, pairing_ttl_ms, None).await
}

pub(super) async fn replacement_material_with_scope(
    station: &ArkretServer,
    controller: &TestActorClient,
    account: &AccountId,
    agent: &AgentRuntimeSession,
    pairing_ttl_ms: u64,
    scope: Option<AgentKeyScope>,
) -> Result<ReplacementMaterial> {
    let renewed: AgentRenewPairingOutcome = serde_json::from_value(
        expect_json(
            controller
                .post(&format!(
                    "/_arkret/self/agents/{}/renew-pairing",
                    agent.agent_account.principal_id
                ))
                .json(&AgentRenewPairingRequestBody {
                    pairing_ttl_ms: Some(pairing_ttl_ms),
                }),
            StatusCode::OK,
        )
        .await?,
    )?;
    let token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
        &json!({"r":renewed.pairing_request_id,"c":renewed.pairing_code}),
    )?);
    let bootstrap:AgentPairingBootstrap=serde_json::from_value(expect_json(station.http().post(station.url("/_arkret/open/agent-pairing/resolve"))
        .json(&arkret_models_collaboration::agent_operations::AgentPairingResolveRequestBody {pairing_token:token}),StatusCode::OK).await?)?;
    let method = bootstrap
        .validated_runtime_identity()
        .map_err(anyhow::Error::msg)?
        .verification_method
        .clone();
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|error| anyhow::anyhow!("runtime key entropy: {error}"))?;
    let key = SigningKey::from_bytes(&seed);
    let builder = arkret_signatures::agent::RuntimeKeyRequestBuilder::new_with_verification_method(
        &key,
        bootstrap.clone(),
        &method,
    );
    let candidate = builder.build_approval_request()?;
    let approval: AgentRuntimeApprovalOutcome = serde_json::from_value(
        expect_json(
            station
                .http()
                .post(station.url("/_arkret/open/agent-pairing/runtime-key-requests"))
                .json(&candidate.body),
            StatusCode::OK,
        )
        .await?,
    )?;
    let principal = controller
        .principal
        .as_ref()
        .context("accepted controller")?;
    let controller_method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    let accepted = controller
        .sdk()
        .committed_event_get(&agent.key_authorization)
        .await?;
    let original = accepted
        .reducer_input()
        .context("accepted original key authorization")?;
    let mut authorization: AgentKeyAuthorizePayload = AgentKeyAuthorizePayload::try_from(original)?;
    if let Some(scope) = scope {
        authorization.agent_key_scope = scope;
    }
    authorization.supersedes = vec![
        arkret_models_collaboration::events_payloads::agent::AgentKeySupersession {
            key_id: authorization.key_id.clone(),
            authorized_event_ref: agent.key_authorization.clone(),
        },
    ];
    authorization.key_id = NonEmptyString::new(method.as_str()).map_err(anyhow::Error::msg)?;
    authorization.verification_method = method.clone();
    authorization.public_key = candidate.body.public_key.clone();
    authorization.issued_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let binding = arkret_models_collaboration::agent_scope::agent_runtime_key_binding_digest(
        &agent.agent_account.principal_id,
        &bootstrap.pairing_request_id,
        &method,
        &authorization.public_key,
        None,
    )?;
    let digest = agent_key_pairing_request_binding_digest(
        ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
        &account.principal_id,
        &agent.agent_account.principal_id,
        &bootstrap.pairing_request_id,
        &approval.approval_request_id,
        renewed.expires_at,
        station.service_id(),
        &binding,
    )?;
    authorization.approval_evidence = AgentKeyApprovalEvidence {
        kind: AgentKeyApprovalEvidenceKind::PairingRequest,
        evidence_ref: None,
        request_canonical_digest: Some(digest),
        pairing_request_id: Some(bootstrap.pairing_request_id.clone()),
        approved_by: Some(account.principal_id.clone()),
    };
    let event = sign(
        arkret_event_draft::build_agent_key_authorize_intent(
            &authorization,
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            ActorId::account(agent.agent_account.clone()),
            ActorId::account(account.clone()),
            agent.delegation.clone(),
            Utc::now(),
        )?
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &controller_method,
        principal.device_signing_key.to_bytes(),
    )?;
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
    let provision_scope = &view
        .key_state
        .as_ref()
        .context("immutable provision scope")?
        .requested_scope;
    let disclosure = requested_scope_disclosure(
        account,
        (controller_method, principal.device_signing_key.to_bytes()),
        &agent.agent_account.principal_id,
        station.service_id(),
        &bootstrap.pairing_request_id,
        provision_scope,
    )?;
    Ok(ReplacementMaterial {
        body: builder
            .build_key_pair_request(approval.approval_request_id, disclosure, event)?
            .body,
        bootstrap,
        key,
    })
}

async fn refusal(
    controller: &TestActorClient,
    url: &str,
    body: &AgentKeyPairRequestBody,
    expected: &str,
) -> Result<(String, bool)> {
    let before = acceptance_rows_with_agent_stores(url, true).await?;
    let response = controller
        .post("/_arkret/gate/account/agent-key-pair")
        .header(
            "Idempotency-Key",
            body.authorize_event.event.event_id.as_str(),
        )
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(body)?)
        .send()
        .await?;
    ensure!(!response.status().is_success(), "{expected} was admitted");
    let status = response.status();
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        problem.status == status.as_u16(),
        "registered Problem status"
    );
    let value = serde_json::to_value(&problem)?;
    ensure!(
        acceptance_rows_with_agent_stores(url, true).await? == before,
        "{expected} refusal changed accepted/Agent state"
    );
    let reason = value.get("reason_code").and_then(serde_json::Value::as_str);
    println!(
        "[agent-pairing] expected_reason={expected} code={} actual_reason={reason:?} full_business_footprint_unchanged=1",
        problem.code()
    );
    println!(
        "[agent-pairing] status={} detail={} diagnostic={:?}",
        problem.status,
        problem.detail.as_str(),
        value.get("reason_detail")
    );
    Ok((expected.to_owned(), reason == Some(expected)))
}

pub async fn run_agent_pairing_expiry_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    let name = "agent-pairing-classification-production";
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
    .context("actual Station process required")?;
    let station = group.server(0);
    let (controller, account) =
        standard_client(station, &coauth, "pairing-controller", CONTROLLER_DEVICE).await?;
    let agent = AgentRuntimeSession::establish(
        station,
        &coauth,
        &controller,
        &account,
        "pairing-reason-agent",
    )
    .await?;
    let (body, expires) = replacement(station, &controller, &account, &agent).await?;
    ensure!(
        ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1
            == "ak.gate.account.command.pair_agent_key.v1"
    );
    let mut observations = Vec::new();
    let mut invalid = body.clone();
    let proof = invalid
        .authorize_event
        .event
        .producer_proof
        .as_mut()
        .context("controller producer proof")?;
    let prefix = proof.jws.rsplit_once('.').context("detached JWS shape")?.0;
    proof.jws = format!("{prefix}.{}", arkret_canonical::base64url_encode([0u8; 64]));
    observations.push(
        refusal(
            &controller,
            &database.connect_url,
            &invalid,
            "proof_invalid",
        )
        .await?,
    );
    let principal = controller
        .principal
        .as_ref()
        .context("accepted controller")?;
    let controller_method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    let mut mismatch = body.clone();
    let mut payload: AgentKeyAuthorizePayload =
        AgentKeyAuthorizePayload::try_from(&body.authorize_event.event)?;
    payload.verification_method = controller_method.clone();
    payload.public_key.kid =
        NonEmptyString::new(controller_method.as_str()).map_err(anyhow::Error::msg)?;
    // A correctly signed envelope with a semantic principal mismatch reaches the real gate.
    let mut raw = arkret_wire::test_support::raw_event_for_actor_at(
        arkret_wire::EventKind::AgentKeyAuthorize.as_str(),
        ScopeRef::Realm {
            realm_id: agent.agent_pcr.clone(),
        },
        ActorId::account(agent.agent_account.clone()),
        serde_json::to_value(payload)?,
        arkret_canonical::normalize_timestamp_canonical(Utc::now()),
    )?;
    raw.executed_by = Some(ActorId::account(account.clone()));
    raw.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(agent.delegation.as_str())
            .map_err(anyhow::Error::msg)?,
    );
    mismatch.authorize_event = arkret_wire::EventAdmissionSubmission::new(sign(
        arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            raw,
            arkret_canonical::DigestSuite::Sha256,
        )?,
        &controller_method,
        principal.device_signing_key.to_bytes(),
    )?);
    observations.push(
        refusal(
            &controller,
            &database.connect_url,
            &mismatch,
            "verification_method_principal_mismatch",
        )
        .await?,
    );
    let wait = (expires - Utc::now()).to_std().unwrap_or_default() + Duration::from_millis(50);
    ensure!(wait <= Duration::from_secs(9));
    tokio::time::sleep(wait).await;
    // The ordinary authenticated view applies permitted expiry housekeeping before the refusal
    // baseline.
    expect_json(
        controller.get(&format!(
            "/_arkret/self/agents/{}",
            agent.agent_account.principal_id
        )),
        StatusCode::OK,
    )
    .await?;
    observations.push(
        refusal(
            &controller,
            &database.connect_url,
            &body,
            "pairing_request_expired",
        )
        .await?,
    );
    let event = sign(
        arkret_event_draft::build_agent_deactivate_intent(
            ActorId::account(agent.agent_account.clone()),
            ActorId::account(account.clone()),
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            agent.delegation.clone(),
            arkret_event_draft::AgentLifecycleState::Active,
            None,
            Utc::now(),
        )?
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &controller_method,
        principal.device_signing_key.to_bytes(),
    )?;
    expect_json(
        controller
            .post(&format!(
                "/_arkret/self/agents/{}/deactivate",
                agent.agent_account.principal_id
            ))
            .json(
                &arkret_models_collaboration::agent_operations::AgentDeactivateRequestBody {
                    reason: None,
                    lifecycle_event: arkret_wire::EventAdmissionSubmission::new(event),
                },
            ),
        StatusCode::OK,
    )
    .await?;
    observations.push(
        refusal(
            &controller,
            &database.connect_url,
            &body,
            "agent_deactivated",
        )
        .await?,
    );
    let missing = observations
        .iter()
        .filter(|(_, passed)| !passed)
        .map(|(name, _)| name)
        .collect::<Vec<_>>();
    ensure!(
        missing.is_empty(),
        "actual pairing classifications missing {missing:?}"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: "agent_pairing_expiry".into(),
            assertions: 9,
        }],
    })
}
