//! Registered Watch commands with an actually provisioned and paired Agent.
use arkret_models_collaboration::authority_commit::{
    AuditPairedEventAcceptanceOutcome, AuditPairedEventUnitKind, AuditPairedEventUnitSubmission,
};
use arkret_models_collaboration::strand_watch_operations::{
    StrandWatchCurrentResponseBody, WatchAuditReadRequestBody, WatchAuditReadResponseBody,
};
use arkret_wire::{EventAdmissionSubmission, EventKind, SemanticRef};

use super::*;
use crate::harness::CanonicalJsonBody;
use crate::scenarios::human_device_producer_live::grant_realm_actions;

pub async fn run_registered_agent_watch_live() -> Result<()> {
    let name = "registered-agent-watch-live";
    let Some(db) = database(name)? else {
        return Ok(());
    };
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let mut env = station_env(&db.connect_url, &issuer);
    env.push((
        "RUST_LOG".to_owned(),
        "coland_storage_postgres=debug,coland_http=debug".to_owned(),
    ));
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(name, &[env]).await?
    else {
        return skip_or_fail(name, "prebuilt Coland unavailable");
    };
    let station = group.server(0);
    let (controller, account) =
        standard_client(station, &issuer, "watch-controller", CONTROLLER_DEVICE).await?;
    let mut operations = runtime_operations().to_vec();
    operations.extend([
        "ak.self.events.command.submit.v1",
        "ak.self.committed_event.read.scan.v1",
        "ak.self.committed_event.stream.subscribe.v1",
        "ak.self.strand.watch.command.audit_read.v1",
        "ak.strand.watch.set",
        "ak.event.read",
        "ak.object.read",
        "ak.strand.read",
        "ak.self.strand.watch.read.current.v1",
        "ak.strand.watch.set.others",
        "ak.audit.accessed",
        "ak.realm.notification.audit",
    ]);
    let created = controller
        .create_realm_with(json!({
            "title":"Agent Watch", "summary":"Registered audit cut", "public":false,
            "join_rule":"public", "plaintext_visible_services":[station.service_id()]
        }))
        .await?;
    let realm: RealmId = created["realm_id"].as_str().context("Realm id")?.parse()?;
    let mut scope = requested_scope(&operations)?;
    scope.resources.push(serde_json::from_value(
        json!({"kind":"realm","realm_id":realm}),
    )?);
    scope.resources.push(serde_json::from_value(
        json!({"kind":"strand","realm_id":realm,
        "resource_ref":controller.default_strand_id(realm.as_str())?}),
    )?);
    let agent = AgentRuntimeSession::establish_observed(
        station,
        AgentSessionIssuer::Fixture(&issuer),
        &controller,
        &account,
        "watch-agent",
        scope,
        None,
    )
    .await?;
    let view = controller
        .sdk()
        .agent_get(agent.agent_account.principal_id.as_str())
        .await?;
    let key_state = view.key_state.context("active Agent key state")?;
    key_state.validate_signer_evidence_delivery()?;
    let Some(arkret_wire::CommittedEventView::Full(source)) =
        key_state.current_key_authorization.as_deref()
    else {
        bail!("active Agent view omitted its accepted authorize original");
    };
    ensure!(
        source.event.actor_id.as_account_id() == Some(&agent.agent_account)
            && source.event.event_id == agent.key_authorization,
        "controller view did not bind the actual paired Agent authorization"
    );
    let mut missing_source = key_state.clone();
    missing_source.current_key_authorization = None;
    ensure!(
        missing_source.validate_signer_evidence_delivery().is_err(),
        "compact-only Agent source bypassed validation"
    );
    let mut wrong_expiry = key_state.clone();
    wrong_expiry.active_authorizations[0].expires_at =
        Some(Utc::now() + chrono::Duration::hours(1));
    ensure!(
        wrong_expiry.validate_signer_evidence_delivery().is_err(),
        "Agent current source did not bind the active authorization expiry"
    );
    let mut tampered_source = key_state.clone();
    if let Some(arkret_wire::CommittedEventView::Full(source)) =
        tampered_source.current_key_authorization.as_deref_mut()
    {
        source.event.payload.insert(
            "audience".to_owned(),
            json!(["ak:did_core:web:other.example"]),
        );
    }
    ensure!(
        tampered_source.validate_signer_evidence_delivery().is_err(),
        "mutated authorize original retained an accepted Agent source"
    );
    let generation: EventId = created["event_response"]["commits"]
        .as_array()
        .and_then(|v| v.last())
        .and_then(|v| v["event_ref"].as_str())
        .context("creator generation")?
        .parse()?;
    let mut joined = MembershipPayload::join(
        realm.clone(),
        ActorId::account(agent.agent_account.clone()),
        "controller admits its Agent",
    );
    joined.agent_controller_binding = Some(AgentControllerMembershipBinding {
        controller_account_id: account.clone(),
        controller_membership_generation_ref: generation,
        controller_terminal_event_ref: None,
    });
    let accepted = controller
        .submit_event(
            realm.as_str(),
            EventKind::MemberState.as_str(),
            joined.to_value()?,
        )
        .await?;
    ensure!(
        accepted["status"] == "committed",
        "Agent membership not accepted: {accepted}"
    );
    grant_realm_actions(
        &controller,
        station,
        realm.as_str(),
        &account,
        &[
            "ak.strand.watch.set.others",
            "ak.audit.accessed",
            "ak.realm.notification.audit",
            "ak.strand.watch.set",
        ],
    )
    .await?;
    grant_realm_actions(
        &controller,
        station,
        realm.as_str(),
        &agent.agent_account,
        &[
            "ak.strand.watch.set.others",
            "ak.audit.accessed",
            "ak.realm.notification.audit",
        ],
    )
    .await?;
    let public_mode = arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload {
        agent_account_id: agent.agent_account.clone(),
        controller_account_id: account.clone(),
        interaction_mode:
            arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public,
        expected_revision: None,
    };
    let mode: arkret_wire::AuthoritySubmitResponseBody = serde_json::from_value(
        controller
            .submit_event(
                realm.as_str(),
                EventKind::AgentInteractionSet.as_str(),
                serde_json::to_value(&public_mode)?,
            )
            .await?,
    )?;
    let arkret_wire::AuthoritySubmitResponseBody::Accepted {
        commit: public_commit,
        ..
    } = mode
    else {
        bail!("Public mode not accepted");
    };
    let strand = controller.default_strand_id(realm.as_str())?;
    let writer = ActorId::account(agent.agent_account.clone());
    let target = ActorId::account(account.clone());
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let observation = WatchAuditReadRequestBody {
        audit_submission: EventAdmissionSubmission::new(agent.author_scoped_event(
            EventKind::AuditAccessed,
            scope.clone(),
            json!({"access_kind":"watch_audit_read", "writer_actor_id":writer,
            "target_actor_id":target, "target_ref":strand, "purpose":"Agent frozen absence",
            "accessed_at":arkret_canonical::format_timestamp_canonical(Utc::now())}),
            Vec::new(),
        )?),
    };
    let read: WatchAuditReadResponseBody = serde_json::from_value(
        expect_json(
            agent
                .runtime
                .post("/_arkret/self/strands/watch/audit-read")
                .canonical_json(&observation)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    read.validate_for_request(&observation, 0)?;
    ensure!(matches!(
        read.current,
        StrandWatchCurrentResponseBody::NeverWritten { .. }
    ));
    let business = agent.author_scoped_event(
        EventKind::StrandWatchSet,
        scope.clone(),
        json!({"strand_id":strand,"watcher_actor_id":target,"level":"all"}),
        Vec::new(),
    )?;
    let audit = agent.author_scoped_event(EventKind::AuditAccessed, scope,
        json!({"access_kind":"watch_set_others","writer_actor_id":writer,"target_actor_id":target,
            "target_ref":strand,"paired_event_id":business.event_id,"purpose":"Agent writes for controller",
            "accessed_at":arkret_canonical::format_timestamp_canonical(Utc::now())}),
        vec![SemanticRef::new(business.event_id.to_string(), "audit_pair")])?;
    let unit = AuditPairedEventUnitSubmission {
        unit_kind: AuditPairedEventUnitKind::AuditPairedEvent,
        events: [business, audit].map(EventAdmissionSubmission::new),
    };
    unit.validate()?;
    let outcome: AuditPairedEventAcceptanceOutcome = serde_json::from_value(
        expect_json(
            agent
                .runtime
                .post("/_arkret/self/events")
                .canonical_json(&unit)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    outcome.validate_for_request(&unit)?;
    let replay: WatchAuditReadResponseBody = serde_json::from_value(
        expect_json(
            agent
                .runtime
                .post("/_arkret/self/strands/watch/audit-read")
                .canonical_json(&observation)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(replay == read, "Agent replay read a later Watch value");
    let private_mode = arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload {
        interaction_mode:
            arkret_models_collaboration::agent_interaction::AgentInteractionMode::Private,
        expected_revision: Some(arkret_wire::CurrentRevision {
            commit_id: public_commit.commit_id,
            stream_position: public_commit.stream_position,
        }),
        ..public_mode
    };
    controller
        .submit_event(
            realm.as_str(),
            EventKind::AgentInteractionSet.as_str(),
            serde_json::to_value(private_mode)?,
        )
        .await?;
    grant_realm_actions(
        &controller,
        station,
        realm.as_str(),
        &agent.agent_account,
        &[
            "ak.strand.watch.set",
            "ak.event.read",
            "ak.object.read",
            "ak.strand.read",
        ],
    )
    .await?;
    let own = agent.author_scoped_event(EventKind::StrandWatchSet, ScopeRef::Realm {realm_id:realm.clone()},
        json!({"strand_id":strand,"watcher_actor_id":ActorId::account(agent.agent_account.clone()),"level":"all"}), Vec::new())?;
    let own_result = expect_json(
        agent
            .runtime
            .post("/_arkret/self/events")
            .canonical_json(&EventAdmissionSubmission::new(own))?,
        StatusCode::OK,
    )
    .await?;
    ensure!(
        own_result["status"] == "committed",
        "private Agent own Watch was not accepted"
    );
    let own_read =
        arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody {
            realm_id: realm.clone(),
            strand_id: strand.parse()?,
            watcher_actor_id: ActorId::account(agent.agent_account.clone()),
        };
    expect_json(
        agent
            .runtime
            .post("/_arkret/self/strands/watch/current")
            .canonical_json(&own_read)?,
        StatusCode::OK,
    )
    .await?;
    let before_private_pair =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &db.connect_url,
            true,
        )
        .await?;
    let private_business = agent.author_scoped_event(EventKind::StrandWatchSet,
        ScopeRef::Realm { realm_id: realm.clone() },
        json!({"strand_id":strand,"watcher_actor_id":target,"level":"participating","expected_value":{"level":"all"}}), Vec::new())?;
    let private_audit = agent.author_scoped_event(EventKind::AuditAccessed,
        ScopeRef::Realm { realm_id: realm.clone() },
        json!({"access_kind":"watch_set_others","writer_actor_id":writer,"target_actor_id":target,
            "target_ref":strand,"paired_event_id":private_business.event_id,"purpose":"Private mode cannot emit shared audit",
            "accessed_at":arkret_canonical::format_timestamp_canonical(Utc::now())}),
        vec![SemanticRef::new(private_business.event_id.to_string(), "audit_pair")])?;
    let private_pair = AuditPairedEventUnitSubmission {
        unit_kind: AuditPairedEventUnitKind::AuditPairedEvent,
        events: [private_business, private_audit].map(EventAdmissionSubmission::new),
    };
    private_pair.validate()?;
    let response = agent
        .runtime
        .post("/_arkret/self/events")
        .canonical_json(&private_pair)?
        .send()
        .await?;
    ensure!(
        response.status().is_client_error(),
        "private Agent emitted a shared audit pair"
    );
    ensure!(
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &db.connect_url,
            true
        )
        .await?
            == before_private_pair,
        "private Agent pair refusal changed accepted state"
    );
    let principal = controller.principal.as_ref().context("controller Device")?;
    let intent = arkret_event_draft::build_agent_pause_intent(
        writer,
        ActorId::account(account),
        ScopeRef::Realm {
            realm_id: agent.agent_pcr.clone(),
        },
        agent.delegation.clone(),
        None,
        Utc::now(),
    )?;
    let paused = sign(
        intent.author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
            .map_err(anyhow::Error::msg)?,
        principal.device_signing_key.to_bytes(),
    )?;
    expect_json(
        controller
            .post(&format!(
                "/_arkret/self/agents/{}/pause",
                agent.agent_account.principal_id
            ))
            .json(
                &arkret_models_collaboration::agent_operations::AgentPauseRequestBody {
                    reason: None,
                    lifecycle_event: EventAdmissionSubmission::new(paused),
                },
            ),
        StatusCode::OK,
    )
    .await?;
    let before =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &db.connect_url,
            true,
        )
        .await?;
    let response = agent
        .runtime
        .post("/_arkret/self/strands/watch/audit-read")
        .canonical_json(&observation)?
        .send()
        .await?;
    ensure!(
        response.status().is_client_error(),
        "paused Agent received a frozen Watch observation"
    );
    ensure!(
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &db.connect_url,
            true
        )
        .await?
            == before,
        "paused replay changed accepted state"
    );
    println!(
        "[registered-agent-watch] real_provision_pairing_session=1 frozen_read=1 paired_write=1 private_own_watch_exception=1 private_shared_pair_zero_effects=1 paused_replay_zero_effects=1"
    );
    Ok(())
}
