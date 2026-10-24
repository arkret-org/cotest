//! Actual Direct participant content ceilings through Coauth and Station.
use arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope;

use super::*;
use crate::harness::CanonicalJsonBody;

pub const REVIEWED_DIRECT_CONTENT_CASES: [&str; 6] = [
    "direct_read_without_realm_grant",
    "direct_registered_write_authority",
    "direct_wrong_participant_binding",
    "service_only_session",
    "direct_authority_cannot_read_ordinary_realm",
    "realm_membership_cannot_replace_direct_participant",
];

fn selectors(realm: &RealmId) -> RequestedAgentSessionGrantScope {
    RequestedAgentSessionGrantScope {
        realm_ids: vec![realm.clone()],
        strand_ids: vec![],
        track_names: vec![],
    }
}

pub(super) async fn issue(
    deployment: &coauth_session_evidence::ActualAgentDeployment,
    agent: &AgentRuntimeSession,
    operations: &[&str],
    realm: &RealmId,
) -> Result<(
    TestActorClient,
    arkret_models_identity::SignedSessionGrantClaims,
)> {
    let (credential, _) = coauth_session_evidence::issue_runtime_session_with_scope(
        &deployment.station,
        deployment.coauth.base_url(),
        &deployment.coauth.pg.connect_url,
        &agent.agent_account.principal_id,
        &agent.key_authorization,
        &agent.verification_method,
        &agent.runtime_key,
        operations,
        selectors(realm),
    )
    .await?;
    let claims = content_session_evidence::observed_issued_claims(&credential)?;
    let runtime = deployment.station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "direct-content-runtime",
        credential,
        agent.runtime_key.clone(),
    )?;
    Ok((runtime, claims))
}

pub(super) async fn refuse(
    deployment: &coauth_session_evidence::ActualAgentDeployment,
    agent: &AgentRuntimeSession,
    operations: &[&str],
    realm: &RealmId,
) -> Result<()> {
    let body = coauth_session_evidence::build_runtime_session_request(
        &deployment.station,
        deployment.coauth.base_url(),
        &agent.agent_account.principal_id,
        &agent.key_authorization,
        &agent.verification_method,
        &agent.runtime_key,
        operations,
        selectors(realm),
    )?;
    coauth_session_evidence::expect_issue_refusal(
        &deployment.station,
        &deployment.coauth.pg.connect_url,
        &format!(
            "{}/_arkret/gate/account/session-grants",
            deployment.coauth.base_url()
        ),
        &body,
        &agent.runtime_key,
        None,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
        None,
    )
    .await
}

async fn commit(controller: &TestActorClient, account: &AccountId, event: &Event) -> Result<()> {
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        controller,
        account,
        &controller.device_id,
        event,
    )
    .await?;
    let stored = controller
        .sdk()
        .committed_event_get(&event.event_id)
        .await?;
    ensure!(stored.reducer_input() == Some(event));
    Ok(())
}

async fn ordinary(
    deployment: &coauth_session_evidence::ActualAgentDeployment,
    agent: &AgentRuntimeSession,
) -> Result<(RealmId, Event)> {
    let controller = &deployment.controller;
    let created=controller.create_realm_with(json!({"title":"Independent ordinary authority",
        "public":false,"join_rule":"public","plaintext_visible_services":[deployment.station.service_id()]})).await?;
    let realm = RealmId::new(created["realm_id"].as_str().context("ordinary Realm")?)?;
    let generation = EventId::new(
        created["event_response"]["commits"]
            .as_array()
            .and_then(|rows| rows.last())
            .and_then(|row| row["event_ref"].as_str())
            .context("controller generation")?,
    )?;
    let mut membership = MembershipPayload::join(
        realm.clone(),
        ActorId::account(agent.agent_account.clone()),
        "Independent ordinary membership",
    );
    membership.agent_controller_binding = Some(AgentControllerMembershipBinding {
        controller_account_id: deployment.account.clone(),
        controller_membership_generation_ref: generation,
        controller_terminal_event_ref: None,
    });
    let event = controller
        .author_event(realm.as_str(), "ak.member.state", membership.to_value()?)
        .await?;
    commit(controller, &deployment.account, &event).await?;
    controller
        .grant_realm_actions_to(
            realm.as_str(),
            &controller.actor,
            &["ak.event.read", "ak.message.create"],
        )
        .await?;
    let strand = arkret_wire::StrandId::new(
        created["default_strand_id"]
            .as_str()
            .context("ordinary Strand")?,
    )?;
    let message = controller.author_event(realm.as_str(), "ak.message.create", json!({
        "strand_id":strand,"track_name":"discussion",
        "content":{"kind":"ak.content.text","body":"Ordinary member payload after Agent join"}
    })).await?;
    commit(controller, &deployment.account, &message).await?;
    Ok((realm, message))
}

pub async fn run_agent_content_direct_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    let fixture = crate::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let contract = &fixture["session_content_authority_contract"];
    ensure!(
        arkret_canonical::sha256_hex(arkret_canonical::canonical_json_bytes(
            &contract["defaults"]
        )?) == "49fad7028393f37d28ca1a4ee06c376d6b16be0a16e4bfa35b77826a53130665",
        "review changed Direct baseline"
    );
    let declared = contract["cases"]
        .as_array()
        .context("Direct canonical cases")?;
    for (name, input, expected) in [
        (
            "direct_read_without_realm_grant",
            json!({"paths":[{"kind":"direct_participant","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":true}],"controller_allows":false,"unrelated_realm_denies":true,"resource_profile":"direct"}),
            "allow",
        ),
        (
            "direct_registered_write_authority",
            json!({"action":"ak.message.create","paths":[{"kind":"direct_participant","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}],"resource_profile":"direct"}),
            "allow",
        ),
        (
            "direct_wrong_participant_binding",
            json!({"same_account_scope":false,"paths":[{"kind":"direct_participant","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":true}],"resource_profile":"direct"}),
            "deny",
        ),
        (
            "service_only_session",
            json!({"action":"service_operation","paths":[],"content_selector_present":false,"source_current":false,"policy_state":"unknown"}),
            "allow",
        ),
        (
            "direct_authority_cannot_read_ordinary_realm",
            json!({"paths":[{"kind":"direct_participant","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":true}]}),
            "deny",
        ),
        (
            "realm_membership_cannot_replace_direct_participant",
            json!({"resource_profile":"direct"}),
            "deny",
        ),
    ] {
        let matches = declared
            .iter()
            .filter(|row| row["name"] == name)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1
                && matches[0]["input"] == input
                && matches[0]["expected"] == expected,
            "review changed Direct case {name}"
        );
    }
    let deployment =
        coauth_session_evidence::actual_agent_deployment("agent-content-direct").await?;
    let station = &deployment.station;
    let controller = &deployment.controller;
    let operations = arkret_schema::agent_runtime_scope::complete_agent_runtime_scope([
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1,
        ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
        ServiceOperationId::SELF_COMMITTED_EVENT_RESOURCE_GET_V1,
        ServiceOperationId::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1,
        ServiceOperationId::SELF_MLS_READ_ROSTER_AUTHORITY_V1,
        ServiceOperationId::SELF_MLS_READ_GROUP_STATE_MATERIAL_V1,
        ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_READ_CLAIM_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
        ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
        ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK_V1,
        "ak.event.read",
        "ak.message.create",
    ])?;
    let actions = operations.iter().map(String::as_str).collect::<Vec<_>>();
    let agent = AgentRuntimeSession::establish_observed(
        station,
        AgentSessionIssuer::Coauth {
            base: deployment.coauth.base_url(),
            database_url: &deployment.coauth.pg.connect_url,
        },
        controller,
        &deployment.account,
        "actual-direct-agent",
        requested_scope(&actions)?,
        None,
    )
    .await?;
    let service_actions = actions
        .iter()
        .copied()
        .filter(|v| ServiceOperationId::from_wire(v).is_some())
        .collect::<Vec<_>>();
    let (service, _) = coauth_session_evidence::issue_runtime_session(
        station,
        deployment.coauth.base_url(),
        &deployment.coauth.pg.connect_url,
        &agent.agent_account.principal_id,
        &agent.key_authorization,
        &agent.verification_method,
        &agent.runtime_key,
        &service_actions,
    )
    .await?;
    let claims = content_session_evidence::observed_issued_claims(&service)?;
    ensure!(
        claims
            .scopes
            .iter()
            .all(|v| ServiceOperationId::from_wire(v).is_some())
    );
    let service_runtime = station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "service-before-direct",
        service,
        agent.runtime_key.clone(),
    )?;
    expect_json(
        service_runtime.get("/_arkret/self/device_messages"),
        StatusCode::OK,
    )
    .await?;
    let founded = direct_evidence::found(controller, &agent, station).await?;
    let read_actions = actions
        .iter()
        .copied()
        .filter(|v| *v != "ak.message.create")
        .collect::<Vec<_>>();
    let (bootstrap_runtime, bootstrap_claims) = issue(
        &deployment,
        &agent,
        &read_actions,
        &founded.coordinates.realm_id,
    )
    .await?;
    ensure!(bootstrap_claims.scopes.iter().any(|v| v == "ak.event.read"));
    ensure!(
        !bootstrap_claims
            .scopes
            .iter()
            .any(|v| v == "ak.message.create")
    );
    let mut joined = Box::pin(direct_mls_evidence::join(
        station,
        controller,
        &agent,
        &bootstrap_runtime,
        founded,
    ))
    .await?;
    let (unrelated, unrelated_original) = ordinary(&deployment, &agent).await?;
    let policy: arkret_models_collaboration::governance::operation_wire::Policy =
        serde_json::from_value(json!({
        "schema":"ak.schema.policy.v1","id":arkret_wire::PolicyId::new_v7_at(Utc::now().timestamp_millis() as u64),
        "realm_id":unrelated,"policy_kind":"agent","default_effect":"allow",
        "created_by":ActorId::account(deployment.account.clone()),"created_at":arkret_canonical::format_timestamp_canonical(Utc::now()),
        "rules":[{"rule_id":"unrelated_agent_read_deny","kind":"agent","effect":"deny",
            "agent_target":{"kind":"agent","agent_account_id":agent.agent_account},"agent_operations":["read"]}]}))?;
    policy.validate()?;
    let set: arkret_models_collaboration::governance::operation_wire::PolicySetStatePayload =
        serde_json::from_value(json!({
        "policy_id":policy.id,"expected_revision":null,"value":policy}))?;
    set.validate()?;
    let event = controller
        .author_event(
            unrelated.as_str(),
            "ak.policy.set",
            serde_json::to_value(set)?,
        )
        .await?;
    commit(controller, &deployment.account, &event).await?;
    let before_leave = controller
        .sdk()
        .scan_commit_stream_to_head(
            unrelated.clone(),
            arkret_wire::CommitStreamRef::Realm {
                realm_id: unrelated.clone(),
            },
            None,
            100,
        )
        .await?;
    ensure!(
        before_leave
            .committed_events
            .iter()
            .any(|row| row.reducer_input() == Some(&unrelated_original))
    );
    controller
        .submit_event(
            unrelated.as_str(),
            "ak.member.state",
            json!({"member_id":ActorId::account(deployment.account.clone()),"membership":"leave"}),
        )
        .await?;
    match controller
        .sdk()
        .scan_commit_stream_to_head(
            unrelated.clone(),
            arkret_wire::CommitStreamRef::Realm {
                realm_id: unrelated.clone(),
            },
            None,
            100,
        )
        .await
    {
        Err(arkret_http_client::Error::Api { status, error }) => ensure!(
            status == StatusCode::FORBIDDEN.as_u16()
                && error.code() == arkret_wire::ErrorCode::CAPABILITY_DENIED,
            "controller lost current stream at the wrong boundary: {status} {error:?}"
        ),
        Err(error) => return Err(error.into()),
        Ok(_) => bail!("controller current stream remained readable after leave"),
    }
    let (read_runtime, claims) = issue(&deployment, &agent, &read_actions, &joined.realm).await?;
    ensure!(claims.scopes.iter().any(|v| v == "ak.event.read"));
    ensure!(
        claims.scope_details.as_ref().context("Direct scope")?["capability_grant_refs"]
            == json!([])
    );
    let original = controller
        .sdk()
        .committed_event_get(&joined.state_ref)
        .await?;
    let read = read_runtime
        .sdk()
        .committed_event_get(&joined.state_ref)
        .await?;
    ensure!(read.reducer_input() == original.reducer_input() && read.reducer_input().is_some());
    refuse(&deployment, &agent, &read_actions, &unrelated).await?;
    let selection = arkret::ParticipationReplaceRequestBody {
        target_scope: arkret::ParticipationScope::Realm {
            realm_id: joined.realm.clone(),
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
    ensure!(
        selected
            .participation_entries
            .iter()
            .any(|entry| entry.target_scope == selection.target_scope
                && entry.selection == selection.selection
                && entry.version == 1)
    );
    let (write_runtime, claims) = issue(&deployment, &agent, &actions, &joined.realm).await?;
    ensure!(claims.scopes.iter().any(|v| v == "ak.message.create"));
    ensure!(
        claims
            .scope_details
            .as_ref()
            .context("Direct write scope")?["capability_grant_refs"]
            == json!([])
    );
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        ScopeRef::Realm {
            realm_id: joined.realm.clone(),
        },
        arkret_wire::EventKind::MessageCreate.as_str(),
        1,
        joined.state_ref.clone(),
        joined.agent.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    let plaintext = arkret_canonical::canonical_json_bytes(&arkret::ContentBlock::text(
        "Direct participant content without literal grant",
    ))?;
    let sealed = arkret::MessageCrypto::encrypt(
        &mut joined.agent,
        "direct-content-case",
        header,
        &plaintext,
    )?;
    let message=arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MessageCreate>::new(
        ScopeRef::Realm {realm_id:joined.realm.clone()},ActorId::account(agent.agent_account.clone()),
        arkret_models_collaboration::events_payloads::MessageCreatePayload::with_encrypted_content(joined.strand.clone(),"discussion",
            arkret_models_crypto::MlsEncryptedPayload::new(sealed.payload.to_envelope()?)?))?
        .with_authorization_ref(arkret_wire::AuthorizationRef::new(
            "ak.authority.direct_conversation_participant.v1".to_owned()).map_err(anyhow::Error::msg)?)
        .with_semantic_ref(arkret_wire::SemanticRef::new(joined.binding.to_string(),"direct_conversation_binding"))
        .author_with_digest_suite(Utc::now(),arkret_canonical::DigestSuite::Sha256)?;
    let message = sign(
        message,
        &agent.verification_method,
        agent.runtime_key.to_bytes(),
    )?;
    let outcome: AuthoritySubmitResponseBody = serde_json::from_value(
        expect_json(
            write_runtime
                .post("/_arkret/self/events")
                .canonical_json(&arkret_wire::EventAdmissionSubmission::new(message.clone()))?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(&outcome,AuthoritySubmitResponseBody::Accepted {status:AuthorityCommitStatus::Committed,commit} if commit.event_ref==message.event_id),
        "Direct Message did not commit: {outcome:?}"
    );
    let stored = controller
        .sdk()
        .committed_event_get(&message.event_id)
        .await?;
    ensure!(stored.reducer_input() == Some(&message));
    let envelope: arkret::EncryptedEnvelope =
        serde_json::from_value(message.payload["encrypted_content"].clone())?;
    let domain = arkret::mls_basic_credential_identity(message.actual_signer())?;
    let header = envelope.reconstruct_pre_encryption_header(
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        message.scope_ref.clone(),
        message.kind.as_str(),
        std::str::from_utf8(&domain)?,
        None,
    )?;
    let payload =
        arkret::mls::encrypted_envelope_to_payload_with_verified_header(&envelope, header)?;
    ensure!(joined.controller.decrypt_payload(&payload)? == plaintext);
    let other = AgentRuntimeSession::establish_observed(
        station,
        AgentSessionIssuer::Coauth {
            base: deployment.coauth.base_url(),
            database_url: &deployment.coauth.pg.connect_url,
        },
        controller,
        &deployment.account,
        "other-real-agent",
        requested_scope(&actions)?,
        None,
    )
    .await?;
    refuse(&deployment, &other, &read_actions, &joined.realm).await?;
    let (ordinary_realm, ordinary_original) = ordinary(&deployment, &other).await?;
    let (ordinary_runtime, _) = issue(&deployment, &other, &read_actions, &ordinary_realm).await?;
    ensure!(
        ordinary_runtime
            .sdk()
            .committed_event_get(&ordinary_original.event_id)
            .await?
            .reducer_input()
            == Some(&ordinary_original)
    );
    refuse(&deployment, &other, &read_actions, &joined.realm).await?;
    println!(
        "[agent-direct-content] real_coauth=1 service_only_before_content=1 actual_direct_founding_mls=1 unrelated_policy_and_controller_loss_isolated=1 direct_read_no_literal_grant=1 direct_write_committed_and_decrypted=1 wrong_participant_no_issue_effect=1 ordinary_membership_cannot_replace_participant=1"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: declared
            .iter()
            .filter_map(|row| {
                let id = row["name"].as_str()?;
                REVIEWED_DIRECT_CONTENT_CASES.contains(&id).then(|| {
                    crate::conformance::CaseExecutionResult {
                        case_id: id.to_owned(),
                        assertions: 1,
                    }
                })
            })
            .collect(),
    })
}
