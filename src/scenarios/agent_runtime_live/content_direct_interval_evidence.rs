//! Actual foreign Contact intervals remain usable without a fresh origin result.
use arkret_models_collaboration::authority_commit::{
    AggregateAcceptanceStatus, DirectConversationFoundingAcceptanceOutcome,
    DirectConversationFoundingUnitKind, DirectConversationFoundingUnitSubmission,
};
use arkret_models_collaboration::contact_operations::*;
use arkret_models_collaboration::direct_conversation::*;
use arkret_models_collaboration::objects::direct_conversation::*;

use super::*;
use crate::harness::CanonicalJsonBody;

pub const REVIEWED_DIRECT_INTERVAL_CONTENT_CASES: [&str; 1] =
    ["direct_verified_interval_without_origin_poll"];

async fn contact(
    client: &TestActorClient,
    peer: &ActorId,
    state: ContactState,
    phase: &str,
) -> Result<ContactListRow> {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let observed = client
            .sdk()
            .contacts_list()
            .await
            .with_context(|| format!("Contact list phase {phase}"))?
            .contacts;
        let summary = observed
            .iter()
            .map(|row| json!({"peer":row.peer,"state":row.state}))
            .collect::<Vec<_>>();
        if let Some(row) = observed
            .into_iter()
            .find(|row| row.peer.contact_actor_id() == *peer && row.state == state)
        {
            println!("[agent-direct-interval-step] phase={phase} expected_state_reached=1");
            return Ok(row);
        }
        ensure!(
            Instant::now() < deadline,
            "normal peer Contact did not converge: phase={phase} expected={state:?} observed={summary:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn capture_contact_diagnostics(
    local: &coauth_session_evidence::ActualAgentDeployment,
    foreign: &coauth_session_evidence::ActualAgentDeployment,
) -> Result<()> {
    let mut result = serde_json::Map::new();
    for (name, deployment) in [("local", local), ("foreign", foreign)] {
        let url = deployment
            .station
            .owned_database_url()
            .context("owned Contact database")?
            .to_owned();
        let value = tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
            let mut connection = postgres::Client::connect(&url, postgres::NoTls)?;
            let mut transaction = connection.transaction()?;
            transaction.batch_execute("SET TRANSACTION READ ONLY")?;
            let value = transaction.query_one("SELECT jsonb_build_object('contacts',(SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb) FROM contacts t),'mirrors',(SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb) FROM contact_verified_mirrors t),'completions',(SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb) FROM contact_completion_intents t),'outbox',(SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb) FROM federation_outbox t),'dead_letters',(SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb) FROM federation_outbox_dead_letter t),'accounts',(SELECT COALESCE(jsonb_agg(jsonb_build_object('pk',a.pk,'principal_id',a.principal_id,'station_id',a.station_id)),'[]'::jsonb) FROM accounts a),'quota_keys',(SELECT COALESCE(jsonb_agg(jsonb_build_object('account_pk',k.account_pk,'key_length',octet_length(k.key_bytes))),'[]'::jsonb) FROM invite_new_source_hmac_keys k),'principal_resolutions',(SELECT COALESCE(jsonb_agg(to_jsonb(p)),'[]'::jsonb) FROM principal_resolutions p),'pcr_genesis_units',(SELECT COALESCE(jsonb_agg(jsonb_build_object('realm_id',p.realm_id,'principal_id',p.principal_id,'station_id',p.station_id)),'[]'::jsonb) FROM pcr_genesis_units p),'roots',(SELECT COALESCE(jsonb_agg(to_jsonb(r)),'[]'::jsonb) FROM realm_authority_root_current_results r))", &[])?.get(0);
            transaction.rollback()?;
            Ok(value)
        }).await??;
        result.insert(name.to_owned(), value);
    }
    let directory =
        std::env::var_os("COTEST_SERVICE_LOG_DIR").context("owned diagnostic directory")?;
    std::fs::write(
        std::path::PathBuf::from(directory).join("direct-contact-private-diagnostic.json"),
        serde_json::to_vec_pretty(&result)?,
    )?;
    Ok(())
}

fn sign_contact(draft: &arkret::PreparedEventDraft, agent: &AgentRuntimeSession) -> Result<Event> {
    let mut event = draft.unsigned_event_for_kind(arkret_wire::event_kind_str::CONTACT_ACCEPTED)?;
    let at = event.created_at;
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        agent.runtime_key.to_bytes(),
        agent.agent_did.clone(),
        agent.verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )?;
    ensure!(
        arkret_wire::Hash::new(
            event.event_digest_with_digest_suite(draft.event_digest.digest_suite()?)?
        )? == draft.event_digest
    );
    Ok(event.into_event())
}

fn verify_contact(
    request: ContactAcceptRequestBody,
    agent: &AgentRuntimeSession,
) -> Result<arkret::VerifiedSubmission<ContactAcceptRequestBody>> {
    let producer = arkret::ProducerVerificationContext {
        actor: ActorId::account(agent.agent_account.clone()),
        verification_method: agent.verification_method.clone(),
        public_key: arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: agent.runtime_key.verifying_key().to_bytes().to_vec(),
        },
        digest_suite: arkret_canonical::DigestSuite::Sha256,
    };
    Ok(arkret::VerifiedSubmission::verify(request, |_| {
        Ok(producer.clone())
    })?)
}

async fn accept(
    runtime: &TestActorClient,
    agent: &AgentRuntimeSession,
    row: ContactListRow,
) -> Result<()> {
    let operation_id = ProtocolOperationId::new(format!("ak:operation:{}", unique_uuid7()))
        .map_err(anyhow::Error::msg)?;
    let idempotency_key = IdempotencyKey::new(format!("ak:idempotency:{}", unique_uuid7()))
        .map_err(anyhow::Error::msg)?;
    let prepared = runtime
        .sdk()
        .contacts_respond(&verify_contact(
            ContactAcceptRequestBody::Prepare(ContactAcceptPrepareRequestBody {
                phase: ContactPreparePhase::Prepare,
                operation_id: operation_id.clone(),
                idempotency_key: idempotency_key.clone(),
                peer: row.peer,
                request_event_ref: row.request_event_ref.context("normal incoming request")?,
                action: ContactAcceptAction::Accept,
                granted_to_peer_scopes: vec![ContactScope::DirectMessage],
            }),
            agent,
        )?)
        .await?;
    let ContactOperationOutcome::Prepared {
        outcome:
            ContactPreparedOutcome::Response {
                operation_id: actual,
                reservation_handle,
                event_draft,
                ..
            },
    } = prepared
    else {
        bail!("Agent normal Contact response was not prepared: {prepared:?}")
    };
    ensure!(actual == operation_id);
    let outcome = runtime
        .sdk()
        .contacts_respond(&verify_contact(
            ContactAcceptRequestBody::Commit(ContactCommitRequestBody {
                phase: ContactCommitPhase::Commit,
                operation_id,
                idempotency_key,
                reservation_handle,
                signed_event: sign_contact(&event_draft, agent)?,
            }),
            agent,
        )?)
        .await?;
    ensure!(
        matches!(
            outcome,
            ContactOperationOutcome::Accepted {
                outcome: ContactAcceptedOutcome::Response { .. }
            }
        ),
        "Agent response was not accepted: {outcome:?}"
    );
    Ok(())
}

fn authored(
    agent: &AgentRuntimeSession,
    kind: &str,
    scope: ScopeRef,
    payload: serde_json::Value,
    refs: Vec<arkret_wire::SemanticRef>,
    at: chrono::DateTime<Utc>,
) -> Result<Event> {
    let mut event = arkret_wire::test_support::raw_event_at(
        kind,
        scope,
        agent.agent_account.principal_id.clone(),
        agent.agent_account.station_id.clone(),
        payload,
        at,
    )?;
    event.semantic_refs = refs;
    let signer = arkret_test_kit::seeded_signer_for_seed(
        agent.runtime_key.to_bytes(),
        agent.agent_did.clone(),
        agent.verification_method.clone(),
    );
    Ok(arkret_test_kit::sign_verifiable_event(
        event,
        &signer,
        arkret_canonical::DigestSuite::Sha256,
    )?
    .expect_verifiable())
}

pub async fn run_agent_content_direct_interval_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    let fixture = crate::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    ensure!(
        arkret_canonical::sha256_hex(arkret_canonical::canonical_json_bytes(
            &fixture["session_content_authority_contract"]["defaults"]
        )?) == "49fad7028393f37d28ca1a4ee06c376d6b16be0a16e4bfa35b77826a53130665",
        "review changed content-authority defaults"
    );
    let cases = fixture["session_content_authority_contract"]["cases"]
        .as_array()
        .context("canonical cases")?;
    let rows = cases
        .iter()
        .filter(|row| row["name"] == REVIEWED_DIRECT_INTERVAL_CONTENT_CASES[0])
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1
            && rows[0]["expected"] == "allow"
            && rows[0]["input"]
                == json!({"resource_profile":"direct","fresh_origin_poll":false,"paths":[{"kind":"direct_participant","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":true}]})
    );
    let mut local =
        coauth_session_evidence::actual_agent_deployment("agent-direct-interval").await?;
    let mut foreign =
        coauth_session_evidence::actual_agent_deployment("agent-contact-origin").await?;
    ensure!(local.station.service_id() != foreign.station.service_id());
    local
        .station
        .restart_with_federation_mesh(&[foreign.station.base_url().to_string()])
        .await?;
    foreign
        .station
        .restart_with_federation_mesh(&[local.station.base_url().to_string()])
        .await?;
    let execution = async {
    let operations = arkret_schema::agent_runtime_scope::complete_agent_runtime_scope([
        ServiceOperationId::SELF_CONTACT_COMMAND_RESPOND_V1,
        ServiceOperationId::SELF_CONTACT_READ_LIST_V1,
        ServiceOperationId::SELF_DIRECT_CONVERSATION_READ_RESOLVE_V1,
        ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
        ServiceOperationId::SELF_COMMITTED_EVENT_RESOURCE_GET_V1,
        ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
        "ak.event.read",
    ])?;
    let actions = operations.iter().map(String::as_str).collect::<Vec<_>>();
    let agent = AgentRuntimeSession::establish_observed(
        &local.station,
        AgentSessionIssuer::Coauth {
            base: local.coauth.base_url(),
            database_url: &local.coauth.pg.connect_url,
        },
        &local.controller,
        &local.account,
        "foreign-contact-interval",
        requested_scope(&actions)?,
        None,
    )
    .await?;
    let holder_url = local.station.owned_database_url().context("native Agent holder database")?.to_owned();
    let holder = agent.agent_account.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut connection = postgres::Client::connect(&holder_url, postgres::NoTls)?;
        let row = connection.query_one("SELECT a.pk,octet_length(k.key_bytes),p.pcr_realm_id FROM accounts a JOIN invite_new_source_hmac_keys k ON k.account_pk=a.pk JOIN principal_resolutions p ON p.principal_id=a.principal_id AND p.station_id=a.station_id WHERE a.principal_id=$1 AND a.station_id=$2", &[&holder.principal_id.as_str(), &holder.station_id.as_str()])?;
        ensure!(row.get::<_,i32>(1) == 32 && !row.get::<_,String>(2).is_empty());
        Ok(())
    }).await??;
    println!("[agent-direct-interval-step] native_holder_account_and_immutable_quota_key_created_with_genesis=1");
    let peer = ContactPeer::Agent {
        actor_id: ActorId::account(agent.agent_account.clone()),
        controller_account_id: local.account.clone(),
    };
    foreign.controller.request_contact_with_peer(peer.clone(),
        arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence::ExplicitAddress).await?;
    let incoming = contact(
        &agent.runtime,
        &ActorId::account(foreign.account.clone()),
        ContactState::PendingIncoming,
        "local_pending_incoming",
    )
    .await?;
    accept(&agent.runtime, &agent, incoming).await.context("Agent Contact respond")?;
    println!("[agent-direct-interval-step] agent_response_accepted=1");
    let accepted = contact(
        &agent.runtime,
        &ActorId::account(foreign.account.clone()),
        ContactState::Accepted,
        "local_accepted",
    )
    .await?;
    contact(
        &foreign.controller,
        &ActorId::account(agent.agent_account.clone()),
        ContactState::Accepted,
        "foreign_accepted",
    )
    .await?;
    ensure!(
        accepted
            .bidirectional_scopes
            .contains(&ContactScope::DirectMessage)
    );
    let round = accepted
        .next_prepare_input
        .context("accepted round")?
        .contact_round_id;
    let resolved = agent
        .runtime
        .sdk()
        .direct_conversation_resolve(&DirectConversationResolveRequestBody {
            peer: ContactPeer::Human {
                account_id: foreign.account.clone(),
            },
        })
        .await?;
    let DirectConversationResolveOutcome::CreationRequired {
        next_founding_input,
    } = resolved
    else {
        bail!("real Agent responder is not founder: {resolved:?}")
    };
    let DirectConversationFoundingAuthorityEvidence::Human {
        contact_round_evidence,
        ..
    } = next_founding_input.founding_authority_evidence
    else {
        bail!("foreign pair incorrectly used controller exception")
    };
    ensure!(
        contact_round_evidence.contact_round_id == round
            && contact_round_evidence.current_proofs.len() == 2
    );
    let expiry = contact_round_evidence
        .current_proofs
        .iter()
        .filter(|proof| proof.issuer_id == *foreign.station.service_id())
        .map(|proof| proof.fresh_until)
        .max()
        .context("real foreign source proof")?;
    let at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let create = authored(
        &agent,
        "ak.realm.create",
        ScopeRef::RealmGenesis,
        serde_json::to_value(direct_conversation_realm_create_payload(
            arkret_wire::GenesisSalt::generate()?,
            local.station.trust_domain().clone(),
            local.station.service_id().clone(),
            at,
        )?)?,
        vec![arkret_wire::SemanticRef::new(
            round.to_string(),
            "direct_conversation_contact_round",
        )],
        at,
    )?;
    let realm = RealmId::from_event_id(&create.event_id);
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let founder = authored(
        &agent,
        "ak.member.state",
        scope.clone(),
        serde_json::to_value(direct_conversation_member_join_payload(
            realm.clone(),
            agent.agent_account.clone(),
        ))?,
        vec![],
        at,
    )?;
    let member = authored(
        &agent,
        "ak.member.state",
        scope.clone(),
        serde_json::to_value(direct_conversation_peer_membership_bootstrap(
            realm.clone(),
            &agent.agent_account,
            [agent.agent_account.clone(), foreign.account.clone()],
        )?)?,
        vec![],
        at,
    )?;
    let strand = authored(
        &agent,
        "ak.strand.create",
        scope,
        serde_json::to_value(direct_conversation_main_strand_create_payload(
            realm.clone(),
            ActorId::account(agent.agent_account.clone()),
            at,
        ))?,
        vec![],
        at,
    )?;
    let unit = DirectConversationFoundingUnitSubmission {
        unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
        idempotency_key: arkret_wire::UuidV7::new(unique_uuid7().parse()?)?,
        events: [create.clone(), founder, member, strand]
            .map(arkret_wire::EventAdmissionSubmission::new),
    };
    unit.validate()?;
    let outcome: DirectConversationFoundingAcceptanceOutcome = serde_json::from_value(
        expect_json(
            agent
                .runtime
                .post("/_arkret/self/events")
                .canonical_json(&unit)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    outcome.validate()?;
    ensure!(outcome.status == AggregateAcceptanceStatus::Committed && outcome.commits.len() == 4);
    for (index, commit) in outcome.commits.iter().enumerate() {
        ensure!(
            commit.event_ref == unit.events[index].event.event_id
                && commit.realm_id == realm
                && commit.stream_position == index as u64
        );
    }
    let (before, claims) = content_direct_evidence::issue(&local, &agent, &actions, &realm).await?;
    ensure!(
        claims.scopes.iter().any(|action| action == "ak.event.read")
            && claims.scope_details.as_ref().context("Direct scope")?["capability_grant_refs"]
                == json!([])
    );
    ensure!(
        before
            .sdk()
            .committed_event_get(&create.event_id)
            .await?
            .reducer_input()
            == Some(&create)
    );
    foreign.station.stop_external_process().await?;
    ensure!(
        foreign
            .station
            .http()
            .get(foreign.station.url("/_arkret/open/service"))
            .send()
            .await
            .is_err(),
        "foreign origin is still reachable"
    );
    println!(
        "[agent-direct-interval] real_contact_both_directions=1 agent_is_normal_round_founder=1 accepted_four_commit_unit=1 initial_read_full=1 foreign_origin_stopped=1 waiting_for_actual_signed_lease_expiry=1"
    );
    while Utc::now() <= expiry {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let (after, claims) = content_direct_evidence::issue(&local, &agent, &actions, &realm).await?;
    ensure!(
        claims.scopes.iter().any(|action| action == "ak.event.read")
            && claims.scope_details.as_ref().context("Direct scope")?["capability_grant_refs"]
                == json!([])
    );
    ensure!(
        after
            .sdk()
            .committed_event_get(&create.event_id)
            .await?
            .reducer_input()
            == Some(&create)
    );
    foreign.station.start_external_process().await?;
    println!(
        "[agent-direct-interval] actual_foreign_signed_contact_lease_expired=1 origin_offline_during_fresh_issue_and_read=1 exact_pair_accepted_interval_used=1 real_coauth_content_issue=1 no_literal_read_grant=1 same_accepted_original_full=1 no_clock_or_database_rewrite=1 origin_restarted=1"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: REVIEWED_DIRECT_INTERVAL_CONTENT_CASES[0].to_owned(),
            assertions: 1,
        }],
    })
    }.await;
    if execution.is_err() {
        let captured = capture_contact_diagnostics(&local, &foreign).await;
        eprintln!(
            "[agent-direct-interval-diagnostic] read_only_snapshot_saved={} raw_local_only=1",
            captured.is_ok()
        );
    }
    execution
}
