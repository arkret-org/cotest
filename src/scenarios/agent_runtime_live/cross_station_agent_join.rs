//! A real controller-signed Agent join fails closed without target authority at G.

use arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent;
use arkret_wire::{ErrorCode, EventKind};

use super::*;
use crate::scenarios::human_device_producer_live::{
    ensure_commit_signed_by, ensure_same_commit, prepare_join, submit_and_expect_commit,
    wait_for_committed,
};

async fn controller_join(
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

async fn no_accepted_join(database: &str, event: &Event) -> Result<()> {
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
        ensure!(
            count == 0,
            "refused Agent join acquired a covering RealmCommit"
        );
        if let Some(row) = connection.query_opt(
            "SELECT state,envelope FROM canonical_events WHERE envelope->>'event_id'=$1",
            &[&event.event_id.as_str()],
        )? {
            ensure!(
                row.get::<_, String>(0) != "committed",
                "refused join became committed"
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

pub async fn run_cross_station_agent_join_refusal() -> Result<()> {
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
    home.station
        .restart_with_federation_mesh(&[governor.station.base_url().to_string()])
        .await?;
    governor
        .station
        .restart_with_federation_mesh(&[home.station.base_url().to_string()])
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
    let agent = AgentRuntimeSession::establish_observed(
        &home.station,
        AgentSessionIssuer::Coauth {
            base: home.coauth.base_url(),
            database_url: &home.coauth.pg.connect_url,
        },
        &home.controller,
        &home.account,
        "cross-station-join-agent",
        requested_scope(&runtime_operations())?,
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
    .context("H: real issuer-bound Agent service session must work before the refused join")?;
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

    let event = agent_join_event(&home, &agent, &realm, &controller_membership.event_ref).await?;
    let producer = event
        .account_device_producer()?
        .context("controller device producer")?;
    ensure!(
        producer.account_id == home.account && event.executed_by.is_none(),
        "the original Agent join must remain controller-signed"
    );
    let submission = crate::publication::initial_submission(event.clone(), "")?;
    let home_database = home.station.owned_database_url().context("H database")?;
    let governor_database = governor
        .station
        .owned_database_url()
        .context("G database")?;
    let before_home = accepted_realm_state(home_database, &realm).await?;
    let before_governor = accepted_realm_state(governor_database, &realm).await?;
    let controller_commit = serde_json::to_value(&controller_membership)?;
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
    let response = crate::harness::send_recorded(
        home.controller
            .post("/_arkret/self/events")
            .json(&submission),
    )
    .await?;
    let problem: arkret_wire::Problem = serde_json::from_value(response.json()?)?;
    ensure!(
        response.status == StatusCode::CONFLICT
            && problem.error_code() == Some(ErrorCode::FailedPrecondition)
            && problem.detail == "Agent has no accepted provision",
        "missing target-Agent authority reached another boundary: {}",
        response.context()
    );
    ensure!(
        accepted_realm_state(home_database, &realm).await? == before_home,
        "H advanced accepted Realm history, membership or replica checkpoints on refusal"
    );
    ensure!(
        accepted_realm_state(governor_database, &realm).await? == before_governor,
        "G advanced accepted Realm history, membership or replica checkpoints on refusal"
    );
    no_accepted_join(home_database, &event).await?;
    no_accepted_join(governor_database, &event).await?;
    expect_json(
        agent.runtime.get("/_arkret/self/device-messages"),
        StatusCode::OK,
    )
    .await
    .context("H: the same Agent service session must remain valid after refusal")?;
    println!(
        "[cross-station-agent-join-refusal] real_coauth=1 independent_h_g_databases=1 controller_foreign_join_accepted=1 actual_h_agent_session_valid=1 controller_signed_agent_join_failed_precondition=1 target_provision_unavailable=1 both_accepted_history_member_checkpoints_unchanged=1 sidecar_history_not_reached=1"
    );
    Ok(())
}
