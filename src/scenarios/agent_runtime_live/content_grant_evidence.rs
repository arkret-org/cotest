//! Real grant alternatives, action/resource correlation and current membership.

use super::*;
use crate::harness::CanonicalJsonBody;

pub const REVIEWED_GRANT_CONTENT_CASES: [&str; 8] = [
    "literal_write_grant",
    "action_resource_cannot_be_spliced",
    "one_complete_path_among_alternatives",
    "revoked_grant_path_cannot_restore",
    "revoked_literal_read_does_not_erase_membership",
    "source_stale_or_unknown",
    "condition_not_satisfied",
    "quota_exhausted",
];

pub(super) struct GrantFixture {
    pub(super) deployment: coauth_session_evidence::ActualAgentDeployment,
    pub(super) agent: AgentRuntimeSession,
    pub(super) realm: RealmId,
    pub(super) generation: EventId,
    pub(super) a: arkret_wire::StrandId,
    pub(super) b: arkret_wire::StrandId,
    pub(super) operations: Vec<String>,
    pub(super) message: Event,
}

impl GrantFixture {
    pub(super) async fn establish() -> Result<Self> {
        Self::establish_scoped(false).await
    }

    pub(super) async fn establish_with_mls() -> Result<Self> {
        Self::establish_scoped(true).await
    }

    async fn establish_scoped(mls: bool) -> Result<Self> {
        let deployment = coauth_session_evidence::actual_agent_deployment(if mls {
            "agent-content-mls"
        } else {
            "agent-content-grants"
        })
        .await?;
        let station = &deployment.station;
        let controller = &deployment.controller;
        let created = controller
            .create_realm_with(json!({
                "title":"Grant source correlation", "public":false, "join_rule":"public",
                "plaintext_visible_services":[station.service_id()]
            }))
            .await?;
        let realm = RealmId::new(created["realm_id"].as_str().context("grant Realm")?)?;
        let a =
            arkret_wire::StrandId::new(created["default_strand_id"].as_str().context("Strand A")?)?;
        let generation = EventId::new(
            created["event_response"]["commits"]
                .as_array()
                .and_then(|rows| rows.last())
                .and_then(|row| row["event_ref"].as_str())
                .context("controller join generation")?,
        )?;
        let b = arkret_wire::StrandId::new(
            controller
                .create_strand(realm.as_str(), "Independent grant resource B")
                .await?,
        )?;
        controller
            .grant_realm_actions_to(
                realm.as_str(),
                &controller.actor,
                &["ak.event.read", "ak.message.create"],
            )
            .await?;
        let mut draft = runtime_operations().to_vec();
        draft.extend([
            ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            ServiceOperationId::SELF_COMMITTED_EVENT_RESOURCE_GET_V1,
            "ak.event.read",
            "ak.message.create",
        ]);
        if mls {
            draft.extend([
                ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1,
                ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
                ServiceOperationId::SELF_KEYS_KEYPACKAGES_READ_CLAIM_V1,
                ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
                ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
                ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK_V1,
                ServiceOperationId::SELF_REALM_READ_STREAMS_V1,
                ServiceOperationId::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1,
                ServiceOperationId::SELF_MLS_READ_ROSTER_AUTHORITY_V1,
                ServiceOperationId::SELF_MLS_READ_GROUP_STATE_MATERIAL_V1,
            ]);
        }
        let operations = arkret_schema::agent_runtime_scope::complete_agent_runtime_scope(draft)?;
        let actions = operations.iter().map(String::as_str).collect::<Vec<_>>();
        let mut scope = requested_scope(&actions)?;
        if mls {
            scope.resources.push(serde_json::from_value(
                json!({"kind":"realm","realm_id":realm}),
            )?);
        } else {
            for strand in [&a, &b] {
                scope.resources.push(serde_json::from_value(
                    json!({"kind":"strand","realm_id":realm,"resource_ref":strand}),
                )?);
            }
        }
        let agent = AgentRuntimeSession::establish_observed(
            station,
            AgentSessionIssuer::Coauth {
                base: deployment.coauth.base_url(),
                database_url: &deployment.coauth.pg.connect_url,
            },
            controller,
            &deployment.account,
            "grant-content-agent",
            scope,
            None,
        )
        .await?;
        let mut join = MembershipPayload::join(
            realm.clone(),
            ActorId::account(agent.agent_account.clone()),
            "accepted grant source member",
        );
        join.agent_controller_binding = Some(AgentControllerMembershipBinding {
            controller_account_id: deployment.account.clone(),
            controller_membership_generation_ref: generation.clone(),
            controller_terminal_event_ref: None,
        });
        committed(
            controller
                .submit_event(realm.as_str(), "ak.member.state", join.to_value()?)
                .await?,
        )?;
        committed(controller.submit_event(realm.as_str(), "ak.agent.interaction.set", serde_json::to_value(
            arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload {
                agent_account_id:agent.agent_account.clone(), controller_account_id:deployment.account.clone(),
                interaction_mode:arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public,
                expected_revision:None,
            })?).await?)?;
        controller
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
        let message = controller
            .author_event(
                realm.as_str(),
                "ak.message.create",
                json!({
                    "strand_id":a,"track_name":"discussion",
                    "content":{"kind":"ak.content.text","body":"Exact resource A content"}
                }),
            )
            .await?;
        let accepted: AuthoritySubmitResponseBody = serde_json::from_value(
            expect_json(
                controller
                    .post("/_arkret/self/events")
                    .canonical_json(&arkret_wire::EventAdmissionSubmission::new(message.clone()))?,
                StatusCode::OK,
            )
            .await?,
        )?;
        ensure!(
            matches!(accepted, AuthoritySubmitResponseBody::Accepted {status:AuthorityCommitStatus::Committed,commit} if commit.event_ref==message.event_id)
        );
        Ok(Self {
            deployment,
            agent,
            realm,
            generation,
            a,
            b,
            operations,
            message,
        })
    }

    pub(super) fn selectors(
        &self,
    ) -> arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope {
        arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope {
            realm_ids: Vec::new(),
            strand_ids: vec![self.a.clone()],
            track_names: vec![arkret_wire::NonEmptyString::new("discussion").expect("fixed track")],
        }
    }

    pub(super) async fn issue(
        &self,
    ) -> Result<(
        TestActorClient,
        arkret_models_identity::SignedSessionGrantClaims,
    )> {
        let operations = self
            .operations
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        self.issue_for(&operations, self.selectors()).await
    }

    pub(super) async fn issue_for(
        &self,
        operations: &[&str],
        selectors: arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope,
    ) -> Result<(
        TestActorClient,
        arkret_models_identity::SignedSessionGrantClaims,
    )> {
        let (credential, _) = coauth_session_evidence::issue_runtime_session_with_scope(
            &self.deployment.station,
            self.deployment.coauth.base_url(),
            &self.deployment.coauth.pg.connect_url,
            &self.agent.agent_account.principal_id,
            &self.agent.key_authorization,
            &self.agent.verification_method,
            &self.agent.runtime_key,
            operations,
            selectors,
        )
        .await?;
        let claims = super::content_session_evidence::observed_issued_claims(&credential)?;
        let client = self.deployment.station.client_with_agent_runtime_grant(
            self.agent.agent_did.as_str(),
            "grant-content-runtime",
            credential,
            self.agent.runtime_key.clone(),
        )?;
        Ok((client, claims))
    }

    pub(super) async fn read_exact(&self, client: &TestActorClient) -> Result<()> {
        let response = expect_json(
            client.get(&format!(
                "/_arkret/self/committed-events/{}",
                self.message.event_id
            )),
            StatusCode::OK,
        )
        .await?;
        let view: arkret_wire::CommittedEventView = serde_json::from_value(response)?;
        ensure!(
            matches!(view,arkret_wire::CommittedEventView::Full(ref full) if full.event==self.message)
        );
        Ok(())
    }

    pub(super) async fn grant(
        &self,
        strand: &arkret_wire::StrandId,
        actions: &[&str],
    ) -> Result<arkret_wire::GrantId> {
        self.grant_with_constraints(strand, actions, Vec::new())
            .await
    }

    pub(super) async fn grant_with_constraints(
        &self,
        strand: &arkret_wire::StrandId,
        actions: &[&str],
        extra: Vec<arkret_models_collaboration::governance::grant_constraint::GrantConstraint>,
    ) -> Result<arkret_wire::GrantId> {
        let mut body = arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody {
            schema: SchemaId::CAPABILITY_V1.to_owned(),
            realm_id: Some(self.realm.clone()),
            issuer_id: ActorId::account(self.deployment.account.clone()),
            subject:
                arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(
                    ActorId::account(self.agent.agent_account.clone()),
                ),
            actions: actions.iter().map(|action| (*action).to_owned()).collect(),
            resources: vec![arkret_wire::WireResourceSelector::strand(
                self.realm.clone(),
                strand.clone(),
            )],
            constraints: vec![serde_json::from_value(
                json!({"constraint_kind":"scope_limitation","effect":"allow",
                "allowed_strand_ids":[strand],"allowed_tracks":["discussion"]}),
            )?],
            issuer_authority_refs: vec![arkret::IssuerAuthorityRef::RealmRoot {
                realm_id: self.realm.clone(),
                authority_event_ref: self.realm.event_id(),
                authority_generation: 0,
            }],
            issued_at: Utc::now(),
        };
        body.constraints.extend(extra);
        let controller = &self.deployment.controller;
        let event = controller
            .author_event(
                self.realm.as_str(),
                "ak.capability.grant",
                serde_json::to_value(
                    arkret_models_collaboration::events_payloads::CapabilityGrantPayload {
                        grant: body,
                    },
                )?,
            )
            .await?;
        crate::scenarios::human_device_producer_live::submit_and_expect_commit(
            controller,
            &self.deployment.account,
            &controller.device_id,
            &event,
        )
        .await?;
        let accepted = controller
            .sdk()
            .committed_event_get(&event.event_id)
            .await?;
        ensure!(accepted.reducer_input() == Some(&event));
        Ok(arkret_wire::GrantId::from_event_id(&event.event_id))
    }

    pub(super) fn message(
        &self,
        strand: &arkret_wire::StrandId,
        grant: &arkret_wire::GrantId,
        text: &str,
    ) -> Result<Event> {
        let message =
            arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MessageCreate>::new(
                ScopeRef::Realm {
                    realm_id: self.realm.clone(),
                },
                ActorId::account(self.agent.agent_account.clone()),
                arkret_models_collaboration::events_payloads::MessageCreatePayload::with_content(
                    strand.clone(),
                    "discussion",
                    arkret_models_collaboration::events_payloads::ContentBlock::text(text),
                ),
            )?
            .with_semantic_ref(arkret_wire::SemanticRef::new(
                grant.to_string(),
                arkret_wire::SEMANTIC_REF_ROLE_AUTHORIZED_BY,
            ))
            .author_with_digest_suite(Utc::now(), arkret_canonical::DigestSuite::Sha256)?;
        sign(
            message,
            &self.agent.verification_method,
            self.agent.runtime_key.to_bytes(),
        )
    }

    pub(super) async fn commit_message(
        &self,
        runtime: &TestActorClient,
        strand: &arkret_wire::StrandId,
        grant: &arkret_wire::GrantId,
        text: &str,
    ) -> Result<Event> {
        let message = self.message(strand, grant, text)?;
        let id = committed(
            expect_json(
                runtime
                    .post("/_arkret/self/events")
                    .canonical_json(&arkret_wire::EventAdmissionSubmission::new(message.clone()))?,
                StatusCode::OK,
            )
            .await?,
        )?;
        ensure!(id == message.event_id);
        let stored = self
            .deployment
            .controller
            .sdk()
            .committed_event_get(&id)
            .await?;
        ensure!(stored.reducer_input() == Some(&message));
        Ok(message)
    }

    pub(super) async fn revoke(&self, grant: &arkret_wire::GrantId) -> Result<()> {
        let id = committed(
            self.deployment
                .controller
                .revoke_realm_grant(self.realm.as_str(), grant.as_str())
                .await?,
        )?;
        let view = self
            .deployment
            .controller
            .sdk()
            .committed_event_get(&id)
            .await?;
        let event = view.reducer_input().context("accepted grant revoke")?;
        ensure!(
            event.kind == arkret_wire::EventKind::CapabilityRevoke
                && event.payload["grant_id"] == grant.as_str()
        );
        Ok(())
    }
}

fn committed(value: serde_json::Value) -> Result<EventId> {
    let outcome: AuthoritySubmitResponseBody = serde_json::from_value(value)?;
    match outcome {
        AuthoritySubmitResponseBody::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit,
        } => Ok(commit.event_ref),
        other => bail!("controller source event was not committed: {other:?}"),
    }
}

fn read_without_write(claims: &arkret_models_identity::SignedSessionGrantClaims) -> Result<()> {
    ensure!(claims.scopes.iter().any(|action| action == "ak.event.read"));
    ensure!(
        !claims
            .scopes
            .iter()
            .any(|action| action == "ak.message.create"),
        "cross-resource grant spliced into write authority"
    );
    ensure!(
        claims
            .scope_details
            .as_ref()
            .context("read scope details")?["capability_grant_refs"]
            == json!([]),
        "membership read fabricated a literal source ref"
    );
    Ok(())
}

pub async fn run_agent_content_grant_production() -> Result<crate::conformance::SuiteExecutionResult>
{
    let fixture = crate::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let contract = &fixture["session_content_authority_contract"];
    ensure!(
        arkret_canonical::sha256_hex(arkret_canonical::canonical_json_bytes(
            &contract["defaults"]
        )?) == "49fad7028393f37d28ca1a4ee06c376d6b16be0a16e4bfa35b77826a53130665",
        "review changed grant-source baseline"
    );
    let declared = contract["cases"]
        .as_array()
        .context("canonical grant source cases")?;
    for (name, input) in [
        (
            "literal_write_grant",
            json!({"action":"ak.message.create","paths":[{"kind":"capability_grant","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}]}),
        ),
        (
            "one_complete_path_among_alternatives",
            json!({"paths":[{"kind":"capability_grant","actions":["ak.event.read"],"resources":["B"],"complete":true,"active":true},{"kind":"membership_read","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":true}]}),
        ),
        (
            "action_resource_cannot_be_spliced",
            json!({"action":"ak.message.create","paths":[{"kind":"capability_grant","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":true},{"kind":"capability_grant","actions":["ak.message.create"],"resources":["B"],"complete":true,"active":true}]}),
        ),
        (
            "revoked_literal_read_does_not_erase_membership",
            json!({"paths":[{"kind":"capability_grant","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":false},{"kind":"membership_read","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":true}]}),
        ),
        (
            "revoked_grant_path_cannot_restore",
            json!({"paths":[{"kind":"capability_grant","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":false}]}),
        ),
        ("source_stale_or_unknown", json!({"source_current":false})),
        (
            "condition_not_satisfied",
            json!({"phase":"payload","action":"ak.message.create","conditions_allow":false,
                "paths":[{"kind":"capability_grant","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}]}),
        ),
        (
            "quota_exhausted",
            json!({"phase":"payload","action":"ak.message.create","quota_available":false,
                "paths":[{"kind":"capability_grant","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}]}),
        ),
    ] {
        let rows = declared
            .iter()
            .filter(|case| case["name"] == name)
            .collect::<Vec<_>>();
        ensure!(
            rows.len() == 1 && rows[0]["input"] == input,
            "review changed grant case {name}"
        );
        let expected = if matches!(
            name,
            "action_resource_cannot_be_spliced"
                | "revoked_grant_path_cannot_restore"
                | "source_stale_or_unknown"
                | "condition_not_satisfied"
                | "quota_exhausted"
        ) {
            "deny"
        } else {
            "allow"
        };
        ensure!(
            rows[0]["expected"] == expected,
            "review changed expected grant outcome {name}"
        );
    }
    let scene = GrantFixture::establish().await?;
    super::content_limit_evidence::run_payload_limits(&scene).await?;
    let _b = scene
        .grant(&scene.b, &["ak.event.read", "ak.message.create"])
        .await?;
    let (runtime, claims) = scene.issue().await?;
    read_without_write(&claims)?;
    scene.read_exact(&runtime).await?;
    let read_a = scene.grant(&scene.a, &["ak.event.read"]).await?;
    let (runtime, claims) = scene.issue().await?;
    read_without_write(&claims)?;
    scene.read_exact(&runtime).await?;
    scene.revoke(&read_a).await?;
    let (runtime, claims) = scene.issue().await?;
    read_without_write(&claims)?;
    scene.read_exact(&runtime).await?;
    let write_a = scene.grant(&scene.a, &["ak.message.create"]).await?;
    let (runtime, claims) = scene.issue().await?;
    ensure!(
        claims
            .scopes
            .iter()
            .any(|action| action == "ak.message.create"),
        "exact current write grant omitted"
    );
    ensure!(
        claims
            .scope_details
            .as_ref()
            .context("write scope details")?["capability_grant_refs"]
            .as_array()
            .context("actual used grant refs")?
            .iter()
            .any(|value| value.as_str() == Some(write_a.as_str()))
    );
    scene
        .commit_message(
            &runtime,
            &scene.a,
            &write_a,
            "Exact literal grant on resource A",
        )
        .await?;
    scene.revoke(&write_a).await?;
    let (_, claims) = scene.issue().await?;
    read_without_write(&claims)?;
    committed(
        scene
            .deployment
            .controller
            .submit_event(
                scene.realm.as_str(),
                "ak.member.state",
                json!({
        "member_id":ActorId::account(scene.agent.agent_account.clone()),"membership":"leave"}),
            )
            .await?,
    )?;
    scene.read_exact(&scene.deployment.controller).await?;
    let url = format!(
        "{}/_arkret/gate/account/session-grants",
        scene.deployment.coauth.base_url()
    );
    let operations = scene
        .operations
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let request = coauth_session_evidence::build_runtime_session_request(
        &scene.deployment.station,
        scene.deployment.coauth.base_url(),
        &scene.agent.agent_account.principal_id,
        &scene.agent.key_authorization,
        &scene.agent.verification_method,
        &scene.agent.runtime_key,
        &operations,
        scene.selectors(),
    )?;
    coauth_session_evidence::expect_issue_refusal(
        &scene.deployment.station,
        &scene.deployment.coauth.pg.connect_url,
        &url,
        &request,
        &scene.agent.runtime_key,
        None,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
        None,
    )
    .await?;
    // With membership withdrawn, the revoked read grant is the only former
    // source on A. Request EventRead alone so no missing write action can mask it.
    let read_operations = operations
        .iter()
        .copied()
        .filter(|action| *action != "ak.message.create")
        .collect::<Vec<_>>();
    let request = coauth_session_evidence::build_runtime_session_request(
        &scene.deployment.station,
        scene.deployment.coauth.base_url(),
        &scene.agent.agent_account.principal_id,
        &scene.agent.key_authorization,
        &scene.agent.verification_method,
        &scene.agent.runtime_key,
        &read_operations,
        scene.selectors(),
    )?;
    coauth_session_evidence::expect_issue_refusal(
        &scene.deployment.station,
        &scene.deployment.coauth.pg.connect_url,
        &url,
        &request,
        &scene.agent.runtime_key,
        None,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
        None,
    )
    .await?;
    println!(
        "[agent-grant-content] actual_current_grants=1 exact_resource_alternatives=1 no_action_resource_splice=1 revoked_read_keeps_membership=1 literal_write_committed=1 withdrawn_source_cannot_restore=1"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: declared
            .iter()
            .filter_map(|case| {
                let name = case["name"].as_str()?;
                REVIEWED_GRANT_CONTENT_CASES.contains(&name).then(|| {
                    crate::conformance::CaseExecutionResult {
                        case_id: name.to_owned(),
                        assertions: 1,
                    }
                })
            })
            .collect(),
    })
}
