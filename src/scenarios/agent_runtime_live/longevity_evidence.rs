//! Real same-key controller renewal and its commit-ordered signed basis.

use arkret_models_collaboration::events_payloads::agent::AgentKeySupersession;

use super::*;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

fn renewal(
    controller: &TestActorClient,
    agent: &AgentRuntimeSession,
    payload: &AgentKeyAuthorizePayload,
) -> Result<Event> {
    let principal = controller
        .principal
        .as_ref()
        .context("accepted controller")?;
    let method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    sign(
        arkret_event_draft::build_agent_key_authorize_intent(
            payload,
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
    )
}

async fn refuse_without_effects(
    controller: &TestActorClient,
    event: Event,
    database_url: &str,
) -> Result<()> {
    let before = acceptance_rows_with_agent_stores(database_url, true).await?;
    let response = controller
        .post("/_arkret/self/events")
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &arkret_wire::EventAdmissionSubmission::new(event),
        )?)
        .send()
        .await?;
    if response.status().is_success() {
        let outcome: AuthoritySubmitOutcome = response.json().await?;
        ensure!(
            matches!(outcome, AuthoritySubmitOutcome::Rejected { .. }),
            "invalid renewal accepted: {outcome:?}"
        );
    } else {
        ensure!(
            response.status().is_client_error(),
            "renewal refusal is an internal failure: {}",
            response.status()
        );
        let _: arkret_wire::Problem = response.json().await?;
    }
    let after = acceptance_rows_with_agent_stores(database_url, true).await?;
    let changed = before
        .as_object()
        .context("footprint tables")?
        .iter()
        .filter(|(table, rows)| after.get(*table) != Some(*rows))
        .map(|(table, _)| table.as_str())
        .collect::<Vec<_>>();
    ensure!(
        after == before,
        "refused renewal changed tables: {changed:?}"
    );
    Ok(())
}

pub(super) async fn renew_with_real_issuer(
    station: &ArkretServer,
    coauth: &crate::scenarios::_helpers::coauth_bootstrap::SpawnedCoauth,
    controller: &TestActorClient,
    agent: &mut AgentRuntimeSession,
) -> Result<()> {
    let original = controller
        .sdk()
        .committed_event_get(&agent.key_authorization)
        .await?;
    let mut payload = AgentKeyAuthorizePayload::try_from(
        original.reducer_input().context("accepted original key")?,
    )?;
    ensure!(payload.expires_at.is_none());
    let started = Instant::now();
    tokio::time::sleep(Duration::from_secs(65)).await;
    ensure!(started.elapsed() >= Duration::from_secs(65));
    let (grant, request) = coauth_session_evidence::issue_runtime_session(
        station,
        coauth.base_url(),
        &coauth.pg.connect_url,
        &agent.agent_account.principal_id,
        &agent.key_authorization,
        &agent.verification_method,
        &agent.runtime_key,
        &runtime_operations(),
    )
    .await
    .context("real issuance after 65 seconds of unrevoked authorization")?;
    let runtime = station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "long-lived-agent",
        grant,
        agent.runtime_key.clone(),
    )?;
    ensure!(
        runtime
            .get("/_arkret/self/device_messages")
            .send()
            .await?
            .status()
            .is_success()
    );
    agent.runtime = runtime;
    agent.issuer_request = Some(request);
    payload.supersedes = vec![AgentKeySupersession {
        key_id: payload.key_id.clone(),
        authorized_event_ref: agent.key_authorization.clone(),
    }];
    payload.issued_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let event = renewal(controller, agent, &payload)?;
    let replacement_started = Instant::now();
    let outcome: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/self/events")
                .header("Content-Type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(
                    &arkret_wire::EventAdmissionSubmission::new(event.clone()),
                )?),
            StatusCode::OK,
        )
        .await?,
    )?;
    let AuthoritySubmitOutcome::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit,
    } = outcome
    else {
        bail!("real issuer same-key renewal failed: {outcome:?}");
    };
    commit.validate_content_address()?;
    crate::scenarios::human_device_producer_live::ensure_commit_signed_by(&commit, station)?;
    ensure!(commit.event_ref == event.event_id);
    let current = controller
        .sdk()
        .agent_get(agent.agent_account.principal_id.as_str())
        .await?
        .key_state
        .context("current replacement key source")?;
    current.validate_signer_evidence_delivery()?;
    ensure!(
        current
            .current_key_authorization
            .as_ref()
            .and_then(|source| source.reducer_input())
            .is_some_and(|source| source.event_id == event.event_id)
    );
    let mut missing = current.clone();
    missing.current_key_authorization = None;
    ensure!(missing.validate_signer_evidence_delivery().is_err());
    let mut replayed = current.clone();
    let root = &mut replayed
        .current_signer_evidence
        .as_mut()
        .context("replacement compact signer root")?
        .authenticated_signer_evidence;
    root.authority_commit_id = original.commit().commit_id.clone();
    let reference = root.signer_evidence_ref()?;
    replayed
        .current_signer_evidence
        .as_mut()
        .context("mutated compact signer root")?
        .signer_resolution_evidence_ref = reference.clone();
    replayed.signer_resolution_evidence_ref = Some(reference);
    ensure!(replayed.validate_signer_evidence_delivery().is_err());
    let mut wrong_subject = current.clone();
    let root = &mut wrong_subject
        .current_signer_evidence
        .as_mut()
        .context("subject-bound compact signer root")?
        .authenticated_signer_evidence;
    root.subject_id = agent.controller_account.principal_id.clone();
    let reference = root.signer_evidence_ref()?;
    wrong_subject
        .current_signer_evidence
        .as_mut()
        .context("mutated subject root")?
        .signer_resolution_evidence_ref = reference.clone();
    wrong_subject.signer_resolution_evidence_ref = Some(reference);
    ensure!(wrong_subject.validate_signer_evidence_delivery().is_err());
    let mut unsigned = current.clone();
    if let Some(source) = unsigned.current_key_authorization.as_mut() {
        let arkret_wire::CommittedEventView::Full(source) = source.as_mut() else {
            bail!("accepted key source is withheld");
        };
        source.event.producer_proof = None;
    }
    ensure!(unsigned.validate_signer_evidence_delivery().is_err());
    coauth_session_evidence::wait_runtime_rejected(
        &agent.runtime,
        "superseded real issuer credential",
        replacement_started,
    )
    .await?;
    let issue_url = format!("{}/_arkret/gate/account/session-grants", coauth.base_url());
    let stale = coauth_session_evidence::fresh_session_request(
        agent
            .issuer_request
            .as_ref()
            .context("original actual issuer intent")?,
        &issue_url,
        &agent.runtime_key,
    )?;
    coauth_session_evidence::expect_issue_refusal(
        station,
        &coauth.pg.connect_url,
        &issue_url,
        &stale,
        &agent.runtime_key,
        None,
        arkret_wire::ErrorCode::SIGNATURE_INVALID,
        Some(arkret_wire::ReasonCode::PROOF_INVALID),
    )
    .await?;
    let (grant, request) = coauth_session_evidence::issue_runtime_session(
        station,
        coauth.base_url(),
        &coauth.pg.connect_url,
        &agent.agent_account.principal_id,
        &event.event_id,
        &agent.verification_method,
        &agent.runtime_key,
        &runtime_operations(),
    )
    .await
    .context("real issuer session for accepted same-key replacement")?;
    agent.runtime = station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "same-key-long-lived-agent",
        grant,
        agent.runtime_key.clone(),
    )?;
    agent.key_authorization = event.event_id;
    agent.issuer_request = Some(request);
    ensure!(
        agent
            .runtime
            .get("/_arkret/self/device_messages")
            .send()
            .await?
            .status()
            .is_success()
    );
    println!(
        "[agent-longevity-session] actual_wall_clock_delay_seconds={} nonexpiring_original_issuance_and_consumer=1 accepted_same_key_renewal=1 exact_current_source_binding=1 missing_source_and_self_consistent_old_root_refused=1 old_credential_superseded_within_60s=1 stale_issuer_intent_zero_ledger_refused=1 actual_replacement_issuer_and_consumer=1 canonical_case_completion_claim=0",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

pub async fn run_agent_same_key_renewal_boundary() -> Result<()> {
    let name = "agent-same-key-renewal";
    let Some(database) = database(name)? else {
        return Ok(());
    };
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(servers) = TestServerGroup::try_multi_external_with_node_envs(
        name,
        &[station_env(&database.connect_url, &issuer)],
    )
    .await?
    else {
        return skip_or_fail(name, "prebuilt Station unavailable");
    };
    let station = servers.server(0);
    let (controller, account) =
        standard_client(station, &issuer, "same-key-controller", CONTROLLER_DEVICE).await?;
    let agent =
        AgentRuntimeSession::establish(station, &issuer, &controller, &account, "same-key-agent")
            .await?;
    let original = controller
        .sdk()
        .committed_event_get(&agent.key_authorization)
        .await?;
    let payload = AgentKeyAuthorizePayload::try_from(
        original.reducer_input().context("accepted authorization")?,
    )?;
    ensure!(payload.expires_at.is_none());
    let view = controller
        .sdk()
        .agent_get(agent.agent_account.principal_id.as_str())
        .await?;
    let state = view.key_state.context("current authorized key")?;
    let [dot] = state.active_authorizations.as_slice() else {
        bail!("first key does not have exactly one accepted dot");
    };
    ensure!(
        dot.authorized_event_ref == agent.key_authorization
            && dot.key_id == payload.key_id
            && dot.expires_at.is_none()
    );
    let mut next = payload.clone();
    next.supersedes = vec![AgentKeySupersession {
        key_id: dot.key_id.clone(),
        authorized_event_ref: dot.authorized_event_ref.clone(),
    }];
    next.issued_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let mut empty_basis = next.clone();
    empty_basis.supersedes.clear();
    refuse_without_effects(
        &controller,
        renewal(&controller, &agent, &empty_basis)?,
        &database.connect_url,
    )
    .await?;
    let mut changed_key = next.clone();
    changed_key.key_id = "unpaired-replacement-key"
        .to_owned()
        .try_into()
        .map_err(anyhow::Error::msg)?;
    refuse_without_effects(
        &controller,
        renewal(&controller, &agent, &changed_key)?,
        &database.connect_url,
    )
    .await?;
    let mut enlarged_scope = next.clone();
    enlarged_scope
        .agent_key_scope
        .actions
        .push("ak.realm.admin".to_owned());
    enlarged_scope.agent_key_scope.actions.sort();
    enlarged_scope.agent_key_scope.actions.dedup();
    refuse_without_effects(
        &controller,
        renewal(&controller, &agent, &enlarged_scope)?,
        &database.connect_url,
    )
    .await?;
    let mut changed_material = next.clone();
    {
        use base64::Engine as _;
        changed_material.public_key.key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(SigningKey::from_bytes(&[91; 32]).verifying_key().as_bytes())
            .try_into()
            .map_err(anyhow::Error::msg)?;
    }
    refuse_without_effects(
        &controller,
        renewal(&controller, &agent, &changed_material)?,
        &database.connect_url,
    )
    .await?;
    let winner = renewal(&controller, &agent, &next)?;
    let mut competing = next.clone();
    competing.expires_at = Some(arkret_canonical::normalize_timestamp_canonical(
        Utc::now() + chrono::Duration::days(1),
    ));
    let loser = renewal(&controller, &agent, &competing)?;
    ensure!(winner.event_id != loser.event_id);
    let before = acceptance_rows_with_agent_stores(&database.connect_url, true).await?;
    let result: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/self/events")
                .header("Content-Type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(
                    &arkret_wire::EventAdmissionSubmission::new(winner.clone()),
                )?),
            StatusCode::OK,
        )
        .await?,
    )?;
    let AuthoritySubmitOutcome::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit,
    } = result
    else {
        bail!("same-key controller renewal was not accepted: {result:?}");
    };
    commit.validate_content_address()?;
    crate::scenarios::human_device_producer_live::ensure_commit_signed_by(&commit, station)?;
    ensure!(commit.event_ref == winner.event_id);
    let after = acceptance_rows_with_agent_stores(&database.connect_url, true).await?;
    for table in ["canonical_events", "realm_commits"] {
        ensure!(
            after[table].as_array().context("accepted rows")?.len()
                == before[table].as_array().context("original rows")?.len() + 1
        );
    }
    let view = controller
        .sdk()
        .agent_get(agent.agent_account.principal_id.as_str())
        .await?;
    let state = view.key_state.context("renewed current key")?;
    ensure!(
        state.authorized_event_ref.as_ref() == Some(&winner.event_id),
        "runtime binding did not advance to the same-key replacement"
    );
    ensure!(state.authorized_verification_method.as_ref() == Some(&payload.verification_method));
    let reference = state
        .signer_resolution_evidence_ref
        .as_ref()
        .context("renewed signer evidence reference")?;
    state
        .current_signer_evidence
        .as_ref()
        .context("renewed signer evidence")?
        .validate_against(reference)?;
    let [dot] = state.active_authorizations.as_slice() else {
        bail!("same-key renewal merged permission heads");
    };
    ensure!(
        dot.authorized_event_ref == winner.event_id
            && dot.key_id == payload.key_id
            && dot.verification_method == payload.verification_method
            && dot.expires_at.is_none()
    );
    let response = controller
        .post("/_arkret/self/events")
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &arkret_wire::EventAdmissionSubmission::new(loser),
        )?)
        .send()
        .await?;
    if response.status().is_success() {
        let result: AuthoritySubmitOutcome = response.json().await?;
        ensure!(
            matches!(result, AuthoritySubmitOutcome::Rejected { .. }),
            "stale same-key basis was accepted: {result:?}"
        );
    } else {
        ensure!(response.status().is_client_error());
        let _: arkret_wire::Problem = response.json().await?;
    }
    ensure!(acceptance_rows_with_agent_stores(&database.connect_url, true).await? == after);
    let view = controller
        .sdk()
        .agent_get(agent.agent_account.principal_id.as_str())
        .await?;
    let state = view.key_state.context("final current key")?;
    ensure!(
        state.active_authorizations.len() == 1
            && state.active_authorizations[0].authorized_event_ref == winner.event_id
            && state.active_authorizations[0].expires_at.is_none()
    );
    println!(
        "[agent-longevity] real_nonexpiring_authorization=1 original_exact_active_dot=1 same_key_material_preserved=1 same_key_controller_event_without_pairing=1 exactly_one_event_commit=1 observed_dot_replaced=1 stale_same_basis_refused=1 empty_basis_unpaired_key_enlarged_scope_refused=1 current_runtime_binding_and_signer_evidence_advanced=1 no_permission_heads_or_earliest_expiry_merge=1 full_refusal_footprint_unchanged=1 canonical_case_completion_claim=0"
    );
    Ok(())
}
