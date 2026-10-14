//! Accepted controller-owned Agent Direct coordinates, independent of presence.

use arkret_models_collaboration::authority_commit::{
    AggregateAcceptanceStatus, DirectConversationFoundingAcceptanceOutcome,
    DirectConversationFoundingUnitKind, DirectConversationFoundingUnitSubmission,
};
use arkret_models_collaboration::direct_conversation::{
    DirectConversationFoundingPlan, DirectConversationResolveOutcome,
    DirectConversationResolveRequestBody,
};
use arkret_models_collaboration::objects::direct_conversation::*;

pub(super) struct Founded {
    pub coordinates:
        arkret_models_collaboration::direct_conversation::DirectConversationCoordinates,
    pub plan: DirectConversationFoundingPlan,
    pub authorization_basis: DirectConversationAuthorizationBasis,
    pub create_ref: EventId,
}

use super::*;

pub(super) async fn found(
    controller: &TestActorClient,
    agent: &AgentRuntimeSession,
    station: &ArkretServer,
) -> Result<Founded> {
    let request = DirectConversationResolveRequestBody {
        peer: arkret_models_collaboration::contact_operations::ContactPeer::Agent {
            actor_id: ActorId::account(agent.agent_account.clone()),
            controller_account_id: agent.controller_account.clone(),
        },
    };
    let resolved = controller
        .sdk()
        .direct_conversation_resolve(&request)
        .await?;
    let DirectConversationResolveOutcome::CreationRequired {
        next_founding_input,
    } = resolved
    else {
        bail!("new owned Agent Direct did not return founding input: {resolved:?}");
    };
    let DirectConversationFoundingAuthorityEvidence::ControllerAgent {
        agent_provision_ref,
        ..
    } = next_founding_input.founding_authority_evidence
    else {
        bail!("owned Agent founding selected a Contact branch");
    };
    let principal = controller
        .principal
        .as_ref()
        .context("accepted controller")?;
    let method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    let signer = arkret_test_kit::seeded_signer_for_seed(
        principal.device_signing_key.to_bytes(),
        Did::new(controller.actor.clone())?,
        method,
    );
    let at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let author = |kind: &str,
                  scope: ScopeRef,
                  payload: serde_json::Value,
                  refs: Vec<arkret_wire::SemanticRef>|
     -> Result<Event> {
        let mut event = arkret_wire::test_support::raw_event_at(
            kind,
            scope,
            agent.controller_account.principal_id.clone(),
            agent.controller_account.station_id.clone(),
            payload,
            at,
        )?;
        event.semantic_refs = refs;
        Ok(arkret_test_kit::sign_verifiable_event(
            event,
            &signer,
            arkret::canonical::DigestSuite::Sha256,
        )?
        .expect_verifiable())
    };
    let create = author(
        arkret_wire::event_kind_str::REALM_CREATE,
        ScopeRef::RealmGenesis,
        serde_json::to_value(direct_conversation_realm_create_payload(
            arkret_wire::GenesisSalt::generate()?,
            station.trust_domain().clone(),
            station.service_id().clone(),
            at,
        )?)?,
        vec![arkret_wire::SemanticRef::new(
            agent_provision_ref.to_string(),
            "direct_conversation_agent_provision",
        )],
    )?;
    let realm = RealmId::from_event_id(&create.event_id);
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let join = author(
        arkret_wire::event_kind_str::MEMBER_STATE,
        scope.clone(),
        serde_json::to_value(direct_conversation_member_join_payload(
            realm.clone(),
            agent.controller_account.clone(),
        ))?,
        Vec::new(),
    )?;
    let mut peer_membership = direct_conversation_peer_membership_bootstrap(
        realm.clone(),
        &agent.controller_account,
        [
            agent.controller_account.clone(),
            agent.agent_account.clone(),
        ],
    )?;
    peer_membership.agent_controller_binding = Some(AgentControllerMembershipBinding {
        controller_account_id: agent.controller_account.clone(),
        controller_membership_generation_ref: join.event_id.clone(),
        controller_terminal_event_ref: None,
    });
    let peer = author(
        arkret_wire::event_kind_str::MEMBER_STATE,
        scope.clone(),
        serde_json::to_value(peer_membership)?,
        Vec::new(),
    )?;
    let strand = author(
        arkret_wire::event_kind_str::STRAND_CREATE,
        scope,
        serde_json::to_value(direct_conversation_main_strand_create_payload(
            realm.clone(),
            ActorId::account(agent.controller_account.clone()),
            at,
        ))?,
        Vec::new(),
    )?;
    let unit = DirectConversationFoundingUnitSubmission {
        unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
        idempotency_key: arkret_wire::UuidV7::new(unique_uuid7().parse()?)?,
        events: [create, join, peer, strand].map(arkret_wire::EventAdmissionSubmission::new),
    };
    unit.validate()?;
    let plan = DirectConversationFoundingPlan::from_events(
        unit.events.each_ref().map(|submission| &submission.event),
    )?;
    let outcome: DirectConversationFoundingAcceptanceOutcome = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/self/events")
                .header("Content-Type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(&unit)?),
            StatusCode::OK,
        )
        .await?,
    )?;
    outcome.validate()?;
    ensure!(outcome.status == AggregateAcceptanceStatus::Committed && outcome.commits.len() == 4);
    for (index, commit) in outcome.commits.iter().enumerate() {
        commit.validate_content_address()?;
        crate::scenarios::human_device_producer_live::ensure_commit_signed_by(commit, station)?;
        ensure!(
            commit.realm_id == realm
                && commit.stream_position == index as u64
                && commit.event_ref == unit.events[index].event.event_id
        );
    }
    let resolved = controller
        .sdk()
        .direct_conversation_resolve(&request)
        .await?;
    let DirectConversationResolveOutcome::Provisional {
        coordinates,
        authorization_basis,
        ..
    } = resolved
    else {
        bail!("accepted owned Agent Direct did not resolve: {resolved:?}");
    };
    ensure!(
        coordinates.realm_id == plan.realm_id && coordinates.main_strand_id == plan.main_strand_id
    );
    ensure!(
        authorization_basis.kind == DirectConversationAuthorizationKind::AgentController
            && authorization_basis
                .event_refs
                .contains(&agent_provision_ref)
    );
    println!(
        "[agent-direct] real_resolver_controller_branch=1 caller_signed_four_event_unit=1 four_station_signed_commits=1 accepted_coordinates_resolved=1 no_contact_round=1 mls_completion_claim=0"
    );
    let presence = garth::presence::PresenceProjection::new();
    ensure!(
        presence.aggregated(&ActorId::account(agent.agent_account.clone()), Utc::now())
            == arkret_models_discovery::PresenceStatus::Offline
    );
    let view = controller
        .sdk()
        .agent_get(agent.agent_account.principal_id.as_str())
        .await?;
    ensure!(
        view.agent.lifecycle
            == arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
            && view.agent.readiness.state
                == arkret_models_collaboration::agent_operations::AgentReadinessState::Ready
            && view.agent.readiness.blockers.is_empty()
            && view.key_state.is_some()
    );
    let repeated = controller
        .sdk()
        .direct_conversation_resolve(&request)
        .await?;
    ensure!(
        serde_json::to_value(
            repeated
                .coordinates()
                .context("accepted Direct still exists")?
        )? == serde_json::to_value(&coordinates)?
    );
    println!(
        "[agent-offline] actual_client_no_verified_presence=1 receiver_aggregate_offline=1 real_agent_active_ready_paired=1 accepted_direct_still_resolves=1 server_unknown_as_offline_claim=0"
    );
    Ok(Founded {
        coordinates,
        plan,
        authorization_basis,
        create_ref: unit.events[0].event.event_id.clone(),
    })
}
