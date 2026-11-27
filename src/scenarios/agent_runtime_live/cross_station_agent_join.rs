//! Exercise home target verification and independent governing membership admission.

use arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent;
use arkret_wire::{ErrorCode, EventKind};

use super::*;
use crate::harness::CanonicalJsonBody;
use crate::scenarios::human_device_producer_live::{
    ensure_commit_signed_by, ensure_same_commit, prepare_join, submit_and_expect_commit,
    wait_for_committed,
};

pub(super) async fn controller_join(
    home: &ActualAgentDeployment,
    governor: &ActualAgentDeployment,
    realm: &RealmId,
) -> Result<arkret_wire::RealmCommit> {
    prepare_join(
        &home.controller,
        realm.as_str(),
        &governor.station,
        RequestId::new_v7_at(Utc::now().timestamp_millis().max(0) as u64).as_str(),
        RealmJoinIntent::MemberJoin,
    )
    .await?;
    let join = home
        .controller
        .author_event(
            realm.as_str(),
            EventKind::MemberState.as_str(),
            MembershipPayload::join(
                realm.clone(),
                ActorId::account(home.account.clone()),
                "Actual owning-H controller joins the independently governed Realm",
            )
            .to_value()?,
        )
        .await?;
    let accepted = submit_and_expect_commit(
        &home.controller,
        &home.account,
        &home.controller.device_id,
        &join,
    )
    .await?;
    ensure_commit_signed_by(&accepted, &governor.station)?;
    ensure_same_commit(
        &accepted,
        &wait_for_committed(&governor.controller, &join.event_id).await?,
    )?;
    ensure_same_commit(
        &accepted,
        &wait_for_committed(&home.controller, &join.event_id).await?,
    )?;
    Ok(accepted)
}

async fn agent_join_event(
    home: &ActualAgentDeployment,
    agent: &AgentRuntimeSession,
    realm: &RealmId,
    controller_join: &EventId,
) -> Result<Event> {
    let mut payload = MembershipPayload::join(
        realm.clone(),
        ActorId::account(agent.agent_account.clone()),
        "Actual owning-H Agent joins under its controller's exact generation",
    );
    payload.agent_controller_binding = Some(AgentControllerMembershipBinding {
        controller_account_id: home.account.clone(),
        controller_membership_generation_ref: controller_join.clone(),
        controller_terminal_event_ref: None,
    });
    let event = home
        .controller
        .author_event(
            realm.as_str(),
            EventKind::MemberState.as_str(),
            payload.to_value()?,
        )
        .await?;
    Ok(event)
}

/// Observe accepted history and Realm-local membership/current/replica checkpoints.
/// H's exact queued forward original is a journal entry, not accepted history.
async fn accepted_realm_state(database: &str, realm: &RealmId) -> Result<serde_json::Value> {
    let database = database.to_owned();
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut connection = postgres::Client::connect(&database, postgres::NoTls)?;
        let mut transaction = connection
            .build_transaction()
            .isolation_level(postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()?;
        let mut snapshot = serde_json::Map::new();
        for table in [
            "canonical_events",
            "realm_commits",
            "realm_commit_event_kinds",
            "realm_authorities",
            "member_state_current_states",
            "current_state_heads",
            "current_state_versions",
            "replica_stream_anchors",
            "replica_authorization_cuts",
            "replica_authorization_rows",
            "realm_state_snapshots",
        ] {
            let accepted = if table == "canonical_events" {
                " AND state='committed'"
            } else {
                ""
            };
            let query = format!(
                "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) \
                 FROM public.{table} r WHERE realm_id=$1{accepted}"
            );
            snapshot.insert(
                table.into(),
                transaction.query_one(&query, &[&realm])?.get(0),
            );
        }
        transaction.commit()?;
        Ok(serde_json::Value::Object(snapshot))
    })
    .await?
}

async fn no_accepted_event(database: &str, event: &Event) -> Result<()> {
    let database = database.to_owned();
    let event = event.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut connection = postgres::Client::connect(&database, postgres::NoTls)?;
        let count: i64 = connection
            .query_one(
                "SELECT count(*) FROM realm_commits WHERE commit_json->>'event_ref'=$1",
                &[&event.event_id.as_str()],
            )?
            .get(0);
        ensure!(count == 0, "refused Event acquired a covering RealmCommit");
        if let Some(row) = connection.query_opt(
            "SELECT state,envelope FROM canonical_events WHERE envelope->>'event_id'=$1",
            &[&event.event_id.as_str()],
        )? {
            ensure!(
                row.get::<_, String>(0) != "committed",
                "refused Event became committed"
            );
            ensure!(
                row.get::<_, serde_json::Value>(1) == serde_json::to_value(&event)?,
                "retained forward journal changed the signed original"
            );
        }
        Ok(())
    })
    .await?
}

enum CrossStationCase {
    JoinedWriter,
    ExpiredRuntime,
}

pub async fn run_cross_station_agent_join() -> Result<()> {
    run_cross_station(CrossStationCase::JoinedWriter).await
}

pub async fn run_cross_station_expired_session() -> Result<()> {
    run_cross_station(CrossStationCase::ExpiredRuntime).await
}

pub(super) async fn independent_stations(
    observer: Option<std::net::SocketAddr>,
) -> Result<(ActualAgentDeployment, ActualAgentDeployment)> {
    let mut home = coauth_session_evidence::actual_agent_deployment("sidecar-owning-h")
        .await
        .context("H: normal Coauth tenant/controller onboarding")?;
    let mut governor = coauth_session_evidence::actual_agent_deployment("sidecar-governor-g")
        .await
        .context("G: normal Coauth tenant/controller onboarding")?;
    ensure!(home.station.service_id() != governor.station.service_id());
    ensure!(home.account.station_id != governor.account.station_id);
    ensure!(
        home.station.owned_database_url().context("H database")?
            != governor
                .station
                .owned_database_url()
                .context("G database")?,
        "H and G must use independent durable databases"
    );
    ensure!(home.coauth.pg.connect_url != governor.coauth.pg.connect_url);
    if let Some(observer) = observer {
        home.station.observe_agent_history_handoff(observer)?;
    }
    home.station
        .restart_with_federation_mesh(&[governor.station.base_url().to_string()])
        .await?;
    governor
        .station
        .restart_with_federation_mesh(&[home.station.base_url().to_string()])
        .await?;
    Ok((home, governor))
}

async fn run_cross_station(case: CrossStationCase) -> Result<()> {
    let (mut home, governor) = independent_stations(None).await?;
    // The two controllers already own normally issued grants. Only future
    // grants issued at H use this shorter lifetime; their clocks remain real.
    {
        use std::io::{Seek, SeekFrom, Write};
        let file = home.coauth.config.as_file_mut();
        file.seek(SeekFrom::Start(0))?;
        let mut config: serde_json::Value = serde_saphyr::from_reader(&mut *file)?;
        config["arkret"]["session_grant_ttl"] = json!(180);
        file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?;
        serde_saphyr::to_io_writer(&mut *file, &config)?;
        file.flush()?;
    }
    home.coauth.restart_same_config().await?;
    home.coauth
        .wait_for_owning_station(std::time::Duration::from_secs(60))
        .await?;

    let created = governor
        .controller
        .create_realm_with(json!({
            "title":"Independent H controller Agent join", "public":false,
            "join_rule":"public",
            "plaintext_visible_services":[home.station.service_id(),governor.station.service_id()]
        }))
        .await
        .context("G: actual ordinary Realm bootstrap")?;
    let realm = RealmId::new(created["realm_id"].as_str().context("G parent Realm")?)?;
    let controller_membership = controller_join(&home, &governor, &realm)
        .await
        .context("H to G: actual controller join and committed replication")?;
    let strand = arkret_wire::StrandId::new(
        created["default_strand_id"]
            .as_str()
            .context("G default Strand")?,
    )?;
    let mut draft = runtime_operations().to_vec();
    draft.extend([
        ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
        "ak.message.create",
    ]);
    let operations = arkret_schema::agent_runtime_scope::complete_agent_runtime_scope(draft)?;
    let actions: Vec<_> = operations.iter().map(String::as_str).collect();
    let mut scope = requested_scope(&actions)?;
    scope.resources.push(serde_json::from_value(
        json!({"kind":"realm","realm_id":realm}),
    )?);
    let agent = AgentRuntimeSession::establish_observed(
        &home.station,
        AgentSessionIssuer::Coauth {
            base: home.coauth.base_url(),
            database_url: &home.coauth.pg.connect_url,
        },
        &home.controller,
        &home.account,
        "cross-station-join-agent",
        scope,
        None,
    )
    .await
    .context("H: actual Agent provision/PCR/runtime pairing and service session")?;
    ensure!(agent.agent_account.station_id == *home.station.service_id());
    expect_json(
        agent.runtime.get("/_arkret/self/device-messages"),
        StatusCode::OK,
    )
    .await
    .context("H: real issuer-bound Agent service session must work before the join")?;
    if matches!(case, CrossStationCase::ExpiredRuntime) {
        use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
        let claims = super::content_session_evidence::observed_issued_metadata(
            &home.coauth.pg.connect_url,
            agent.runtime.session().credential(),
        )
        .await?;
        ensure!(
            claims.account_id == agent.agent_account
                && claims
                    .scopes
                    .iter()
                    .any(|s| s == ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1)
        );
        return check_expired_session(
            &agent.runtime,
            claims.expires_at,
            home.station.owned_database_url().context("H database")?,
            governor
                .station
                .owned_database_url()
                .context("G database")?,
            || {
                agent.author_scoped_event(
                    EventKind::MessageCreate,
                    ScopeRef::Realm {
                        realm_id: realm.clone(),
                    },
                    serde_json::to_value(MessageCreatePayload::with_content(
                        strand.clone(),
                        "discussion",
                        ContentBlock::text("Expired before admission"),
                    ))?,
                    vec![],
                )
            },
        )
        .await;
    }
    let view = home
        .controller
        .sdk()
        .agent_get(agent.agent_account.principal_id.as_str())
        .await?;
    let key_state = view.key_state.context("H: accepted active Agent key")?;
    key_state.validate_signer_evidence_delivery()?;
    let Some(arkret_wire::CommittedEventView::Full(source)) =
        key_state.current_key_authorization.as_deref()
    else {
        bail!("H omitted the actual Agent's accepted key authorization");
    };
    ensure!(
        source.event.actor_id.as_account_id() == Some(&agent.agent_account)
            && source.event.event_id == agent.key_authorization,
        "H's current key source differs from this paired Agent"
    );

    check_governed_join_and_messages(
        &home,
        &governor,
        &realm,
        &strand,
        &agent,
        &controller_membership,
        &actions,
    )
    .await
}

async fn check_governed_join_and_messages(
    home: &ActualAgentDeployment,
    governor: &ActualAgentDeployment,
    realm: &RealmId,
    strand: &arkret_wire::StrandId,
    agent: &AgentRuntimeSession,
    controller_membership: &arkret_wire::RealmCommit,
    actions: &[&str],
) -> Result<()> {
    let event = agent_join_event(home, agent, realm, &controller_membership.event_ref).await?;
    let producer = event
        .account_device_producer()?
        .context("controller device producer")?;
    ensure!(
        producer.account_id == home.account && event.executed_by.is_none(),
        "the original Agent join must remain controller-signed"
    );

    let home_database = home.station.owned_database_url().context("H database")?;
    let governor_database = governor
        .station
        .owned_database_url()
        .context("G database")?;
    let before_home = accepted_realm_state(home_database, realm).await?;
    let before_governor = accepted_realm_state(governor_database, realm).await?;
    let controller_commit = serde_json::to_value(controller_membership)?;
    for snapshot in [&before_home, &before_governor] {
        ensure!(
            snapshot["canonical_events"]
                .as_array()
                .context("accepted canonical rows")?
                .iter()
                .any(|row| row["envelope"]["event_id"] == controller_membership.event_ref.as_str()),
            "Station lost the controller's accepted join original"
        );
        ensure!(
            snapshot["realm_commits"]
                .as_array()
                .context("held RealmCommit rows")?
                .iter()
                .any(|row| row["commit_json"] == controller_commit),
            "Station lost the exact governing Commit for the controller join"
        );
    }
    let members = before_governor["member_state_current_states"]
        .as_array()
        .context("G: authoritative member current rows")?;
    let controller_actor = ActorId::account(home.account.clone()).to_string();
    let agent_actor = ActorId::account(agent.agent_account.clone()).to_string();
    ensure!(
        members
            .iter()
            .any(|row| row["member_id"] == controller_actor
                && row["membership"] == "join"
                && row["current_commit_id"] == controller_membership.commit_id.as_str()),
        "G: the exact controller joined generation is not current"
    );
    ensure!(
        !members
            .iter()
            .any(|row| row["member_id"] == agent_actor && row["membership"] == "join"),
        "G: Agent was already joined before this request"
    );
    let accepted = submit_and_expect_commit(
        &home.controller,
        &home.account,
        &home.controller.device_id,
        &event,
    )
    .await
    .context("G: accept exact verified home controller join")?;
    ensure_commit_signed_by(&accepted, &governor.station)?;
    ensure_same_commit(
        &accepted,
        &wait_for_committed(&governor.controller, &event.event_id).await?,
    )?;
    ensure_same_commit(
        &accepted,
        &wait_for_committed(&home.controller, &event.event_id).await?,
    )?;

    let invalid = agent_join_event(home, agent, realm, &controller_membership.event_ref).await?;
    ensure!(
        invalid.event_id != event.event_id,
        "test requires a new join intent"
    );
    let before_home = accepted_realm_state(home_database, realm).await?;
    let before_governor = accepted_realm_state(governor_database, realm).await?;
    let response = crate::harness::send_recorded(
        home.controller
            .post("/_arkret/self/events")
            .canonical_json(&crate::publication::initial_submission(
                invalid.clone(),
                "",
            )?)?,
    )
    .await?;
    let problem: arkret_wire::Problem = serde_json::from_value(response.json()?)?;
    ensure!(
        problem.error_code() == Some(ErrorCode::FailedPrecondition)
            && problem
                .extensions
                .get("reason_code")
                .and_then(serde_json::Value::as_str)
                == Some(arkret_wire::ReasonCode::INVALID_MEMBERSHIP_TRANSITION),
        "G must reject the second join from its current member state: {}",
        response.context()
    );
    ensure!(accepted_realm_state(home_database, realm).await? == before_home);
    ensure!(accepted_realm_state(governor_database, realm).await? == before_governor);
    no_accepted_event(home_database, &invalid).await?;
    no_accepted_event(governor_database, &invalid).await?;
    expect_json(
        agent.runtime.get("/_arkret/self/device-messages"),
        StatusCode::OK,
    )
    .await?;
    println!(
        "[cross-station-agent-join] controller and Agent joined at G; identical governing Commit at H; new duplicate-state join refused without accepted writes"
    );
    check_cross_station_messages(
        home,
        governor,
        realm,
        strand,
        agent,
        actions,
        arkret::IssuerAuthorityRef::OwnedAgent {
            realm_id: realm.clone(),
            controller_account_id: home.account.clone(),
            controller_join_event_id: controller_membership.event_ref.clone(),
            agent_join_event_id: accepted.event_ref.clone(),
        },
    )
    .await?;
    Ok(())
}

async fn forward_attempt(database: &str, event: &Event) -> Result<Option<serde_json::Value>> {
    let database = database.to_owned();
    let id = event.event_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
        Ok(db.query_opt("SELECT to_jsonb(f) FROM authority_forward_attempts f JOIN canonical_events e ON e.pk=f.event_pk WHERE e.envelope->>'event_id'=$1",&[&id])?.map(|row| row.get(0)))
    }).await?
}

async fn check_cross_station_messages(
    home: &ActualAgentDeployment,
    governor: &ActualAgentDeployment,
    realm: &RealmId,
    strand: &arkret_wire::StrandId,
    agent: &AgentRuntimeSession,
    actions: &[&str],
    issuer_authority: arkret::IssuerAuthorityRef,
) -> Result<()> {
    use arkret_models_collaboration::agent_interaction::{
        AgentInteractionMode, AgentInteractionSetPayload,
    };
    use arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope;
    let home_db = home.station.owned_database_url().context("H database")?;
    let governor_db = governor
        .station
        .owned_database_url()
        .context("G database")?;
    let mode = home
        .controller
        .author_event(
            realm.as_str(),
            "ak.agent.interaction.set",
            serde_json::to_value(AgentInteractionSetPayload {
                agent_account_id: agent.agent_account.clone(),
                controller_account_id: home.account.clone(),
                interaction_mode: AgentInteractionMode::Public,
                expected_commit_id: None,
            })?,
        )
        .await?;
    let public_commit = submit_and_expect_commit(
        &home.controller,
        &home.account,
        &home.controller.device_id,
        &mode,
    )
    .await
    .context("H to G: controller explicitly publishes Agent")?;
    ensure_commit_signed_by(&public_commit, &governor.station)?;
    ensure_same_commit(
        &public_commit,
        &wait_for_committed(&governor.controller, &mode.event_id).await?,
    )?;
    println!(
        "[cross-station-agent-mode] G committed the original controller-signed public setting"
    );
    governor
        .controller
        .grant_realm_actions_to_client(realm.as_str(), &home.controller, &["ak.message.create"])
        .await?;
    let terminal_grant = |action: &str| {
        json!({
            "grant": {
                "schema": "ak.schema.capability.v1",
                "realm_id": realm,
                "issuer_id": ActorId::account(home.account.clone()),
                "subject": ActorId::account(agent.agent_account.clone()),
                "actions": [action],
                "resources": [{"kind": "realm", "realm_id": realm, "match_scope": "realm_wide"}],
                "constraints": [{
                    "constraint_kind": "authority_control",
                    "effect": "allow",
                    "max_authority_depth": 0,
                    "authority_regrant_allowed": false
                }],
                "issuer_authority_refs": [issuer_authority],
                "issued_at": arkret_canonical::format_timestamp_canonical(Utc::now())
            }
        })
    };
    let outside = home
        .controller
        .author_event(
            realm.as_str(),
            EventKind::CapabilityGrant.as_str(),
            terminal_grant("ak.reaction.add"),
        )
        .await?;
    let response = home
        .controller
        .post("/_arkret/self/events")
        .canonical_json(&crate::publication::initial_submission(
            outside.clone(),
            "",
        )?)?
        .send()
        .await?;
    ensure!(response.status() == StatusCode::CONFLICT);
    let refusal: arkret_wire::Problem = response.json().await?;
    ensure!(
        refusal
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str)
            == Some("agent_grant_exceeds_requested_scope"),
        "unexpected out-of-provision grant refusal: {}",
        refusal.code()
    );
    ensure!(
        forward_attempt(home_db, &outside)
            .await?
            .is_none_or(|f| f["peer_request_json"].is_null())
    );
    no_accepted_event(governor_db, &outside).await?;
    let owner_grant = home
        .controller
        .author_event(
            realm.as_str(),
            EventKind::CapabilityGrant.as_str(),
            terminal_grant("ak.message.create"),
        )
        .await?;
    let grant_commit = submit_and_expect_commit(
        &home.controller,
        &home.account,
        &home.controller.device_id,
        &owner_grant,
    )
    .await
    .context("G: accept the original owner's terminal grant")?;
    ensure_commit_signed_by(&grant_commit, &governor.station)?;
    ensure_same_commit(
        &grant_commit,
        &wait_for_committed(&governor.controller, &owner_grant.event_id).await?,
    )?;
    let grant = arkret_identifiers::GrantId::from_event_id(&owner_grant.event_id).to_string();
    println!("[cross-station-agent-grant] G committed the controller's terminal grant");
    home.controller
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
                expected_version: 0,
            },
        )
        .await?;
    let (outcome, request) = coauth_session_evidence::issue_runtime_session_outcome(
        &home.station,
        home.coauth.base_url(),
        &home.coauth.pg.connect_url,
        &agent.agent_account.principal_id,
        &agent.key_authorization,
        &agent.verification_method,
        &agent.runtime_key,
        actions,
        RequestedAgentSessionGrantScope {
            realm_ids: vec![realm.clone()],
            strand_ids: vec![],
            track_names: vec![],
        },
    )
    .await
    .context("H: issue authenticated session bounded by G")?;
    ensure!(
        outcome
            .granted_scope
            .iter()
            .any(|a| a == "ak.message.create"),
        "G did not permit message creation"
    );
    let until = outcome.expires_at;
    let runtime = home
        .station
        .client_with_issued_agent_session(
            agent.agent_did.as_str(),
            RUNTIME_FRAGMENT,
            agent.runtime_key.clone(),
            home.coauth.base_url(),
            request,
            outcome,
        )
        .await?;
    let message = |body: &str| {
        use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
        let payload = MessageCreatePayload::with_content(
            strand.clone(),
            "discussion",
            ContentBlock::text(body),
        );
        agent.author_scoped_event(
            EventKind::MessageCreate,
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            serde_json::to_value(payload)?,
            vec![arkret_wire::SemanticRef::new(
                grant.clone(),
                arkret_wire::SEMANTIC_REF_ROLE_AUTHORIZED_BY,
            )],
        )
    };
    let allowed = message("G accepts this signed Agent message")?;
    let response = expect_json(
        runtime
            .post("/_arkret/self/events")
            .canonical_json(&arkret_wire::EventAdmissionSubmission::new(allowed.clone()))?,
        StatusCode::OK,
    )
    .await?;
    let arkret_wire::AuthoritySubmitResponseBody::Accepted { commit, .. } =
        serde_json::from_value(response)?
    else {
        bail!("expected committed Agent message")
    };
    ensure!(commit.event_ref == allowed.event_id);
    ensure_commit_signed_by(&commit, &governor.station)?;
    ensure_same_commit(
        &commit,
        &wait_for_committed(&governor.controller, &allowed.event_id).await?,
    )?;
    let revoke = governor
        .controller
        .revoke_realm_grant(realm.as_str(), &grant)
        .await?;
    let arkret_wire::AuthoritySubmitResponseBody::Accepted { commit: revoke, .. } =
        serde_json::from_value(revoke)?
    else {
        bail!("G did not commit the grant revocation");
    };
    let view = governor
        .controller
        .sdk()
        .committed_event_get(&revoke.event_ref)
        .await?;
    let original = view
        .reducer_input()
        .context("G must retain its grant revocation")?;
    ensure!(
        original.kind == EventKind::CapabilityRevoke
            && original.payload["grant_id"] == grant.as_str()
    );
    let refused = message("G revoked this writer")?;
    let rejected = runtime
        .post("/_arkret/self/events")
        .canonical_json(&arkret_wire::EventAdmissionSubmission::new(refused.clone()))?
        .send()
        .await?;
    ensure!(
        rejected.status() == StatusCode::FORBIDDEN && Utc::now() < until,
        "expected refusal with a live home session"
    );
    let problem: arkret_wire::Problem = rejected.json().await?;
    ensure!(
        problem.error_code() == Some(ErrorCode::CapabilityDenied),
        "unexpected G refusal: {}",
        problem.code()
    );
    let attempt = forward_attempt(home_db, &refused)
        .await?
        .context("H did not attempt this G refusal")?;
    ensure!(
        attempt["status"] == "rejected"
            && attempt["reason_code"] == problem.code()
            && !attempt["peer_request_json"].is_null(),
        "G rejection not recorded at H"
    );
    no_accepted_event(governor_db, &refused).await?;
    println!(
        "[cross-station-agent-message] G committed the live write and refused the writer after revocation"
    );
    check_expired_session(&runtime, until, home_db, governor_db, || {
        message("Expired home session")
    })
    .await
}

async fn check_expired_session(
    runtime: &TestActorClient,
    expires_at: chrono::DateTime<Utc>,
    home_db: &str,
    governor_db: &str,
    sign_message: impl FnOnce() -> Result<Event>,
) -> Result<()> {
    let before_expiry = expires_at - chrono::Duration::seconds(15);
    tokio::time::sleep((before_expiry - Utc::now()).to_std().unwrap_or_default()).await;
    expect_json(runtime.get("/_arkret/self/device-messages"), StatusCode::OK).await?;
    ensure!(Utc::now() < expires_at, "live control must precede expiry");
    let delay = (expires_at - Utc::now()).to_std().unwrap_or_default()
        + std::time::Duration::from_millis(100);
    tokio::time::sleep(delay).await;
    let expired = sign_message()?;
    let response = runtime
        .post("/_arkret/self/events")
        .canonical_json(&arkret_wire::EventAdmissionSubmission::new(expired.clone()))?
        .send()
        .await?;
    ensure!(response.status() == StatusCode::UNAUTHORIZED);
    let problem: arkret_wire::Problem = response.json().await?;
    // The issuer may report its grant inactive on a fresh lookup. An already
    // authenticated cached grant exposes its exact expiry to the Station.
    ensure!(
        Utc::now() >= expires_at
            && (problem.error_code() == Some(ErrorCode::AuthExpired)
                || (problem.error_code() == Some(ErrorCode::Unauthenticated)
                    && problem.detail == "session grant is not active")),
        "unexpected expired session response: {}",
        problem.code()
    );
    ensure!(
        forward_attempt(home_db, &expired).await?.is_none(),
        "H created a forward attempt after expiry"
    );
    no_accepted_event(governor_db, &expired).await?;
    println!(
        "[cross-station-agent-expiry] live control passed; H refused the expired session ({}) without a forward attempt; G has no commit",
        problem.code()
    );
    Ok(())
}
