//! Actual Coauth ceilings and endpoint-specific Sidecar bootstrap/payload gates.

use arkret_models_collaboration::sidecar_operations::*;

use super::*;
use crate::harness::CanonicalJsonBody;
use crate::scenarios::mls_lifecycle_live::{ACTIVE_SUITE, Member, upload_public_blob};
use crate::scenarios::sidecar_authority_live::private_reply::{self, JoinObserver};

pub const REVIEWED_SIDECAR_CONTENT_CASES: [&str; 17] = [
    "sidecar_read_without_literal_grant",
    "sidecar_read_does_not_grant_write",
    "issue_pending_mls_is_only_ceiling",
    "bootstrap_desired_not_yet_effective",
    "bootstrap_wrong_endpoint",
    "bootstrap_missing_add_welcome_claim_lineage",
    "desired_cannot_read_payload",
    "effective_sidecar_payload",
    "wrong_sidecar_binding",
    "queued_welcome_after_desired_revoke",
    "future_epoch_material_after_desired_revoke",
    "valid_future_epoch_material",
    "realm_grant_cannot_replace_sidecar_authority",
    "sidecar_explicit_write_grant",
    "sidecar_write_grant_without_effective",
    "sidecar_write_grant_after_desired_loss",
    "sidecar_material_not_a_write_grant_operation",
];

async fn other_controller_content(
    deployment: &coauth_session_evidence::ActualAgentDeployment,
    agent: &AgentRuntimeSession,
    read: &TestActorClient,
    realm: &RealmId,
    strand: &arkret_wire::StrandId,
    own_message: &Event,
) -> Result<()> {
    let client = coauth_session_evidence::additional_controller(
        deployment,
        "bob",
        "ak:device:01904100-0000-7000-8000-000000002302",
    )
    .await?;
    let principal = client
        .principal
        .as_ref()
        .context("actual second controller")?;
    let account = AccountId::new(
        principal.core_id.clone(),
        deployment.station.service_id().clone(),
    );
    let join = MembershipPayload::join(
        realm.clone(),
        ActorId::account(account.clone()),
        "Independent Sidecar controller",
    );
    let joined: AuthoritySubmitOutcome = serde_json::from_value(
        client
            .submit_event(realm.as_str(), "ak.member.state", join.to_value()?)
            .await?,
    )?;
    ensure!(matches!(
        joined,
        AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            ..
        }
    ));
    deployment
        .controller
        .grant_realm_actions_to(
            realm.as_str(),
            &client.actor,
            &["ak.event.read", "ak.message.create"],
        )
        .await?;
    let controller = Member {
        client: client.clone(),
        account: account.clone(),
        actor: ActorId::account(account.clone()),
        device: principal.device_id.clone(),
        method: DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
            .map_err(anyhow::Error::msg)?,
        key: principal.device_signing_key.clone(),
        authorize_event_id: principal.founding_authorize_event_id.clone(),
    };
    let operation = ProtocolOperationId::new(format!("ak:operation:{}", unique_uuid7()))
        .map_err(anyhow::Error::msg)?;
    let prepare = SidecarEnsureRequestBody::Prepare(SidecarEnsurePrepareRequestBody {
        phase: SidecarEnsurePreparePhase::Prepare,
        operation_id: operation.clone(),
        idempotency_key: IdempotencyKey::new(format!("other-prepare-{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?,
        source_realm_id: realm.clone(),
        controller_account_id: account.clone(),
        context_ref: SidecarContextRef::Strand {
            strand_id: strand.clone(),
        },
    });
    let SidecarEnsureOutcome::PreparedNew(prepared) = client
        .sdk()
        .agent_sidecar_ensure(&client.verify_publication(prepare)?)
        .await?
    else {
        bail!("new independent Sidecar required")
    };
    let create = client.sign_prepared_contact_event(
        &prepared.create_event_draft,
        arkret_wire::EventKind::SidecarCreate.as_str(),
    )?;
    let attach = client.sign_prepared_contact_event(
        &prepared.context_attach_event_draft,
        arkret_wire::EventKind::SidecarContextAttach.as_str(),
    )?;
    let request = SidecarEnsureRequestBody::Commit(SidecarEnsureCommitRequestBody {
        phase: SidecarEnsureCommitPhase::Commit,
        operation_id: operation,
        idempotency_key: IdempotencyKey::new(format!("other-commit-{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?,
        reservation_handle: prepared.reservation_handle,
        create_event: create,
        context_attach_event: attach,
    });
    let SidecarEnsureOutcome::Accepted(accepted) = client
        .sdk()
        .agent_sidecar_ensure(&client.verify_publication(request.clone())?)
        .await?
    else {
        bail!("independent Sidecar acceptance required")
    };
    let sidecar = accepted.sidecar_id;
    let view = client.sdk().agent_sidecar_get(&sidecar).await?;
    ensure!(
        view.sidecar.controller_account_id == account
            && view.sidecar.realm_id == *realm
            && view.desired_agent_ids.is_empty()
    );
    let scope = ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    ensure!(scope != own_message.scope_ref);
    let binding = arkret::MlsGovernanceBindingPayload::sidecar(
        realm.clone(),
        sidecar,
        None,
        0,
        0,
        0,
        view.mls_context.participant_authority_digest,
        view.mls_context.authority_stream_head,
    )?;
    let mut group = controller
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &binding)?;
    let leaf = crate::scenarios::cross_station_mls_welcome::genesis_creator_leaf_authority(
        &mut group,
        &controller,
    )?;
    let (info, tree) = group.public_group_state_bytes()?;
    let info = upload_public_blob(&client, realm, &info).await?;
    let tree = upload_public_blob(&client, realm, &tree).await?;
    let mut genesis = client
        .author_event(
            realm.as_str(),
            "ak.mls.genesis",
            json!({
        "cipher_suite":ACTIVE_SUITE,"group_info_ref":info,"ratchet_tree_ref":tree,
        "governance_binding":binding,"creator_leaf_authority":leaf,
        "created_at":arkret_canonical::format_timestamp_canonical(Utc::now())}),
        )
        .await?;
    genesis.scope_ref = scope;
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut genesis,
        controller.key.to_bytes(),
    )?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &client,
        &account,
        client.device_id.as_str(),
        &genesis,
    )
    .await?;
    let state =
        crate::scenarios::mls_lifecycle_live::accepted_full_view(&client, &genesis.event_id)
            .await?;
    let request = arkret::MlsMemberRosterAuthorityReadRequestBody {
        realm_id: realm.clone(),
        effective_scope: genesis.scope_ref.clone(),
        mls_group_id: genesis.scope_ref.canonical_mls_group_id()?,
        target_commit_event_ref: genesis.event_id.clone(),
        target_epoch: 0,
        caller_actor_id: controller.actor.clone(),
        cursor: None,
    };
    let page = client.sdk().self_mls_roster_authority(&request).await?;
    ensure!(page.roster.records.len() == 1 && page.roster.next_cursor.is_none());
    let peer =
        arkret::verify_mls_member_roster_authority_pages(std::slice::from_ref(&page), &request)?;
    let material = client
        .sdk()
        .self_mls_group_state_material(&arkret::mls_roster_genesis_material_request(
            &peer,
            &page.roster.manifest,
        ))
        .await?;
    arkret::install_verified_mls_self_roster_bindings(&mut group, &[page], &request, &material)
        .map_err(anyhow::Error::msg)?;
    let (target, _) = controller_message(&controller, &mut group, &state, strand).await?;
    let (grant, _) = deployment
        .controller
        .grant_realm_actions_to(realm.as_str(), agent.agent_did.as_str(), &["ak.event.read"])
        .await?;
    let grant = arkret_wire::GrantId::new(grant)?;
    let original = deployment
        .controller
        .sdk()
        .committed_event_get(&EventId::from_token_bytes(grant.token_bytes())?)
        .await?;
    let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(serde_json::to_value(
            &original
                .reducer_input()
                .context("parent literal read grant")?
                .payload,
        )?)?;
    ensure!(payload.grant.actions == vec!["ak.event.read"]);
    ensure!(matches!(payload.grant.subject,
        arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(ref actor)
        if actor==&ActorId::account(agent.agent_account.clone())));
    ensure!(
        read.sdk()
            .committed_event_get(&own_message.event_id)
            .await?
            .reducer_input()
            == Some(own_message)
    );
    crate::harness::expect_api_error(
        read.get(&format!(
            "/_arkret/self/committed-events/{}",
            target.event_id
        )),
        StatusCode::NOT_FOUND,
        arkret_wire::ErrorCode::NOT_FOUND,
    )
    .await?;
    ensure!(
        client
            .sdk()
            .committed_event_get(&target.event_id)
            .await?
            .reducer_input()
            == Some(&target)
    );
    let leave = MembershipPayload::transition(
        arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Leave,
        controller.actor.clone(),
        "Recheck ordinary controller qualification after departure",
    );
    let left: AuthoritySubmitOutcome = serde_json::from_value(
        client
            .submit_event(realm.as_str(), "ak.member.state", leave.to_value()?)
            .await?,
    )?;
    ensure!(matches!(
        left,
        AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            ..
        }
    ));
    let denied = SidecarEnsureRequestBody::Prepare(SidecarEnsurePrepareRequestBody {
        phase: SidecarEnsurePreparePhase::Prepare,
        operation_id: ProtocolOperationId::new(format!("ak:operation:{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?,
        idempotency_key: IdempotencyKey::new(format!("departed-prepare-{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?,
        source_realm_id: realm.clone(),
        controller_account_id: account,
        context_ref: SidecarContextRef::Strand {
            strand_id: strand.clone(),
        },
    });
    crate::harness::expect_api_error(
        client
            .post("/_arkret/self/agent-sidecars:ensure")
            .canonical_json(&denied)?,
        StatusCode::FORBIDDEN,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
    )
    .await?;
    ensure!(
        read.sdk()
            .committed_event_get(&own_message.event_id)
            .await?
            .reducer_input()
            == Some(own_message)
    );
    println!(
        "[agent-other-sidecar] actual_second_controller_onboarded=1 accepted_same_realm_join=1 independent_sidecar_genesis=1 actual_other_private_message=1 parent_literal_read_grant_retained=1 own_sidecar_payload_full=1 other_sidecar_payload_not_delivered=1 actual_owner_original_full=1 departed_controller_fresh_ensure_denied=1 other_owner_departure_preserves_own_read=1"
    );
    Ok(())
}

async fn advance_epoch_material(
    controller: &Member,
    agent: &AgentRuntimeSession,
    read: &TestActorClient,
    group: &mut arkret::ArkretMlsGroup,
    agent_group: &mut arkret::ArkretMlsGroup,
    scope: &ScopeRef,
) -> Result<arkret_wire::CommittedEventFullView> {
    let ScopeRef::Sidecar {
        realm_id,
        sidecar_id,
    } = scope
    else {
        bail!("native Sidecar scope required")
    };
    let snapshot = controller
        .client
        .sdk()
        .realm_state_snapshot_head(realm_id)
        .await?;
    let base: arkret_wire::MlsGroupCurrent = snapshot
        .current_state_entries
        .iter()
        .find_map(|row| {
            let arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::MlsGroup { scope_ref },
                value,
                ..
            } = row
            else {
                return None;
            };
            (scope_ref == scope).then(|| serde_json::from_value(value.clone()))
        })
        .context("current Sidecar epoch")??;
    ensure!(base.epoch == 1 && group.epoch() == 1 && agent_group.epoch() == 1);
    let view = controller
        .client
        .sdk()
        .agent_sidecar_get(sidecar_id)
        .await?;
    ensure!(
        view.desired_agent_ids == vec![agent.agent_account.principal_id.clone()]
            && view.effective_agent_ids == vec![agent.agent_account.principal_id.clone()]
    );
    let binding = arkret::MlsGovernanceBindingPayload::sidecar(
        realm_id.clone(),
        sidecar_id.clone(),
        Some(base.current_mls_commit_event_ref.clone()),
        base.epoch,
        base.epoch + 1,
        base.current_key_access_revision,
        view.mls_context.participant_authority_digest,
        view.mls_context.authority_stream_head,
    )?;
    let update = group.self_update_commit_with_governance_binding(&binding)?;
    let payload = arkret::MlsCommitPayload::new(
        base.current_mls_commit_event_ref.clone(),
        base.current_key_access_revision,
        &update,
        binding,
    )?;
    let mut event = controller
        .client
        .author_event(
            realm_id.as_str(),
            "ak.mls.commit",
            serde_json::to_value(payload)?,
        )
        .await?;
    event.scope_ref = scope.clone();
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut event,
        controller.key.to_bytes(),
    )?;
    let journal = tempfile::tempdir()?;
    let path = journal.path().join("pending-controller.json");
    let mut file = std::fs::File::create(&path)?;
    use std::io::Write as _;
    file.write_all(&serde_json::to_vec(&group.export_state_record()?)?)?;
    file.sync_all()?;
    let pending: arkret::MlsGroupStateRecord = serde_json::from_slice(&std::fs::read(&path)?)?;
    *group = arkret::ArkretMlsGroup::restore_from_state_record(&pending)?;
    let submission =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::MlsCommit(
            arkret_wire::MlsCommitSubmission {
                commit_event: event.clone(),
                welcomes: vec![],
                idempotency_key: arkret_wire::UuidV7::new(
                    crate::scenarios::mls_lifecycle_live::fresh_uuid_v7().parse()?,
                )?,
            },
        );
    let (status, result) =
        crate::scenarios::mls_lifecycle_live::post_json(&controller.client, &submission).await?;
    ensure!(
        status == StatusCode::OK,
        "Sidecar real future Update refused: {status} {result}"
    );
    let accepted = crate::scenarios::mls_lifecycle_live::accepted_full_view(
        &controller.client,
        &event.event_id,
    )
    .await?;
    ensure!(group.install_accepted_commit(&accepted, &base)? == 2);
    let received = read.sdk().committed_event_get(&event.event_id).await?;
    let arkret_wire::CommittedEventView::Full(received) = received else {
        bail!("current effective Agent did not receive actual future epoch material")
    };
    ensure!(received == accepted && agent_group.install_accepted_commit(&received, &base)? == 2);
    for (http, participant, actor) in [
        (
            controller.client.sdk(),
            &mut *group,
            controller.actor.clone(),
        ),
        (
            read.sdk(),
            &mut *agent_group,
            ActorId::account(agent.agent_account.clone()),
        ),
    ] {
        let request = arkret::MlsMemberRosterAuthorityReadRequestBody {
            realm_id: realm_id.clone(),
            effective_scope: scope.clone(),
            mls_group_id: scope.canonical_mls_group_id()?,
            target_commit_event_ref: event.event_id.clone(),
            target_epoch: 2,
            caller_actor_id: actor,
            cursor: None,
        };
        let page = http.self_mls_roster_authority(&request).await?;
        ensure!(page.roster.records.len() == 2 && page.roster.next_cursor.is_none());
        let peer = arkret::verify_mls_member_roster_authority_pages(
            std::slice::from_ref(&page),
            &request,
        )?;
        let material = http
            .self_mls_group_state_material(&arkret::mls_roster_genesis_material_request(
                &peer,
                &page.roster.manifest,
            ))
            .await?;
        arkret::install_verified_mls_self_roster_bindings(
            participant,
            &[page],
            &request,
            &material,
        )
        .map_err(anyhow::Error::msg)?;
    }
    let path = journal.path().join("updated-agent.json");
    let mut file = std::fs::File::create(&path)?;
    file.write_all(&serde_json::to_vec(&agent_group.export_state_record()?)?)?;
    file.sync_all()?;
    let state: arkret::MlsGroupStateRecord = serde_json::from_slice(&std::fs::read(&path)?)?;
    *agent_group = arkret::ArkretMlsGroup::restore_from_state_record(&state)?;
    ensure!(agent_group.epoch() == 2);
    Ok(accepted)
}

pub(super) async fn controller_message(
    controller: &Member,
    group: &mut arkret::ArkretMlsGroup,
    state: &arkret_wire::CommittedEventFullView,
    strand: &arkret_wire::StrandId,
) -> Result<(Event, Vec<u8>)> {
    let scope = state.event.scope_ref.clone();
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        arkret_wire::EventKind::MessageCreate.as_str(),
        group.epoch(),
        state.event.event_id.clone(),
        group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    let plaintext = arkret_canonical::canonical_json_bytes(&arkret::ContentBlock::text(
        "Endpoint-specific actual Sidecar content",
    ))?;
    let sealed = arkret::MessageCrypto::encrypt(group, "sidecar-content", header, &plaintext)?;
    let payload =
        arkret_models_collaboration::events_payloads::MessageCreatePayload::with_encrypted_content(
            strand.clone(),
            "discussion",
            arkret_models_crypto::MlsEncryptedPayload::new(sealed.payload.to_envelope()?)?,
        );
    let mut event = controller
        .client
        .author_event(
            scope.realm_id().as_str(),
            "ak.message.create",
            serde_json::to_value(payload)?,
        )
        .await?;
    event.scope_ref = scope;
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut event,
        controller.key.to_bytes(),
    )?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &controller.client,
        &controller.account,
        controller.device.as_str(),
        &event,
    )
    .await?;
    ensure!(
        controller
            .client
            .sdk()
            .committed_event_get(&event.event_id)
            .await?
            .reducer_input()
            == Some(&event)
    );
    Ok((event, plaintext))
}

fn agent_message(
    agent: &AgentRuntimeSession,
    group: &mut arkret::ArkretMlsGroup,
    state: &arkret_wire::CommittedEventFullView,
    strand: &arkret_wire::StrandId,
    grant: &arkret_wire::GrantId,
) -> Result<(Event, Vec<u8>)> {
    let scope = state.event.scope_ref.clone();
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        "ak.message.create",
        group.epoch(),
        state.event.event_id.clone(),
        group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    let plaintext = arkret_canonical::canonical_json_bytes(&arkret::ContentBlock::text(
        "Explicitly granted actual Sidecar reply",
    ))?;
    let encrypted = arkret::MessageCrypto::encrypt(group, unique_uuid7(), header, &plaintext)?;
    let authored = arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MessageCreate>::new(
        scope, ActorId::account(agent.agent_account.clone()),
        arkret_models_collaboration::events_payloads::MessageCreatePayload::with_encrypted_content(
            strand.clone(), "discussion", arkret_models_crypto::MlsEncryptedPayload::new(encrypted.payload.to_envelope()?)?,
        ),
    )?.with_semantic_ref(arkret_wire::SemanticRef::new(grant.to_string(), arkret_wire::SEMANTIC_REF_ROLE_AUTHORIZED_BY))
        .author_with_digest_suite(Utc::now(), arkret_canonical::DigestSuite::Sha256)?;
    Ok((
        sign(
            authored,
            &agent.verification_method,
            agent.runtime_key.to_bytes(),
        )?,
        plaintext,
    ))
}

pub(super) fn open_message(group: &mut arkret::ArkretMlsGroup, event: &Event) -> Result<Vec<u8>> {
    let envelope: arkret::EncryptedEnvelope =
        serde_json::from_value(event.payload["encrypted_content"].clone())?;
    let domain = arkret::mls_basic_credential_identity(event.actual_signer())?;
    let header = envelope.reconstruct_pre_encryption_header(
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        event.scope_ref.clone(),
        event.kind.as_str(),
        std::str::from_utf8(&domain)?,
        None,
    )?;
    let payload =
        arkret::mls::encrypted_envelope_to_payload_with_verified_header(&envelope, header)?;
    Ok(group.decrypt_payload(&payload)?)
}

struct PendingPayload<'a> {
    read: &'a TestActorClient,
    strand: &'a arkret_wire::StrandId,
    deployment: &'a coauth_session_evidence::ActualAgentDeployment,
    actions: &'a [&'a str],
    genesis: &'a Event,
}

#[async_trait::async_trait(?Send)]
impl JoinObserver for PendingPayload<'_> {
    async fn before_submission(
        &self,
        controller: &Member,
        agent: &AgentRuntimeSession,
        submission: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
        claim_request: &arkret_models_crypto::KeyPackagesClaimRequestBody,
    ) -> Result<()> {
        use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;

        use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;
        let SelfAuthoritySubmitRequest::MlsCommit(original) = submission else {
            bail!("actual Add/Welcome submission required")
        };
        ensure!(original.welcomes.len() == 1);
        for kind in ["wrong_endpoint", "missing_add_lineage"] {
            let mut invalid = original.clone();
            invalid.idempotency_key = arkret_wire::UuidV7::new(
                crate::scenarios::mls_lifecycle_live::fresh_uuid_v7().parse()?,
            )?;
            let welcome = &mut invalid.welcomes[0];
            if kind == "wrong_endpoint" {
                welcome.recipient_endpoint =
                    arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
                        verification_method: DidUrl::new(format!(
                            "{}#not-the-current-endpoint",
                            agent.agent_did
                        ))
                        .map_err(anyhow::Error::msg)?,
                    };
            } else {
                let identity = arkret::ArkretMlsIdentity::new_agent(
                    ActorId::account(agent.agent_account.clone()),
                    agent.verification_method.clone(),
                    agent.key_authorization.clone(),
                    ArkretMlsSigner::from_ed25519_signing_key(agent.runtime_key.clone()),
                )?;
                let package = identity.key_package_record()?;
                let upload = identity.signed_key_packages_upload_request(
                    std::slice::from_ref(&package),
                    agent.verification_method.as_str(),
                )?;
                ensure!(
                    agent
                        .runtime
                        .sdk()
                        .keypackages_upload(&upload)
                        .await?
                        .accepted
                        == 1
                );
                let mut candidate = serde_json::to_value(claim_request)?;
                let mut entropy = [0u8; 16];
                getrandom::fill(&mut entropy)
                    .map_err(|error| anyhow::anyhow!("claim entropy: {error}"))?;
                candidate["claim_request_id"] = json!(URL_SAFE_NO_PAD.encode(entropy));
                candidate["target_keypackage_ref"] = json!(package.keypackage_ref);
                let mut claim: arkret_models_crypto::KeyPackagesClaimRequestBody =
                    serde_json::from_value(candidate)?;
                let bytes = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
                    &claim.unsigned_request(),
                    &claim.service_binding,
                    &claim.requester_authorization,
                )?;
                let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device {
                    signature,
                    ..
                } = &mut claim.requester_authorization
                else {
                    bail!("normal controller device claim required")
                };
                signature.sig = arkret_wire::Base64UrlString::new(
                    URL_SAFE_NO_PAD.encode(controller.key.sign(&bytes).to_bytes()),
                )
                .map_err(anyhow::Error::msg)?;
                let claimed = controller.client.sdk().keypackages_claim(&claim).await?;
                ensure!(
                    claimed.claims.len() == 1
                        && claimed.claims[0].keypackage_ref == package.keypackage_ref.as_str()
                );
                let second: arkret_wire::KeypackageClaimId =
                    serde_json::from_value(json!(claimed.claims[0].claim_id))?;
                ensure!(
                    second != welcome.keypackage_claim_ref,
                    "second claim must differ from actual Add"
                );
                welcome.keypackage_claim_ref = second;
            }
            let mut unsigned = serde_json::to_value(&*welcome)?;
            unsigned
                .as_object_mut()
                .context("Welcome object")?
                .remove("producer_proof");
            welcome.producer_proof = arkret_signatures::detached_object::sign_detached_object(
                &unsigned,
                arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
                controller.method.clone(),
                Utc::now(),
                &controller.key,
            )?;
            let before = acceptance_rows_with_agent_stores(
                self.deployment
                    .station
                    .owned_database_url()
                    .context("owned Station database")?,
                true,
            )
            .await?;
            let (status, code) = (
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
            );
            let problem = crate::harness::expect_api_error(
                controller
                    .client
                    .post("/_arkret/self/events")
                    .canonical_json(&SelfAuthoritySubmitRequest::MlsCommit(invalid))?,
                status,
                code,
            )
            .await?;
            if kind == "wrong_endpoint" {
                ensure!(
                    problem
                        .detail
                        .contains("Welcome recipient's endpoint package"),
                    "wrong endpoint did not reach the actual claim binding gate"
                );
            }
            ensure!(
                acceptance_rows_with_agent_stores(
                    self.deployment
                        .station
                        .owned_database_url()
                        .context("owned Station database")?,
                    true
                )
                .await?
                    == before,
                "{kind} altered accepted, current, Agent or delivery business state"
            );
            let (queued, _) =
                crate::scenarios::mls_lifecycle_live::recipient_welcomes(self.read).await?;
            ensure!(queued.is_empty(), "rejected {kind} supplied a Welcome");
            println!(
                "[agent-sidecar-lineage] rejected={kind} real_controller_signature=1 real_add_and_claim=1 full_business_footprint_unchanged=1 no_welcome_delivered=1"
            );
        }
        Ok(())
    }

    async fn before_consume(
        &self,
        controller: &Member,
        agent: &AgentRuntimeSession,
        group: &mut arkret::ArkretMlsGroup,
        agent_group: &mut arkret::ArkretMlsGroup,
        accepted: &arkret_wire::CommittedEventFullView,
        durable_state_path: &std::path::Path,
    ) -> Result<()> {
        let ScopeRef::Sidecar { sidecar_id, .. } = &accepted.event.scope_ref else {
            bail!("Sidecar required")
        };
        let view = controller
            .client
            .sdk()
            .agent_sidecar_get(sidecar_id)
            .await?;
        ensure!(
            view.desired_agent_ids == vec![agent.agent_account.principal_id.clone()]
                && view.effective_agent_ids.is_empty()
        );
        let (event, _) = controller_message(controller, group, accepted, self.strand).await?;
        crate::harness::expect_api_error(
            self.read.get(&format!(
                "/_arkret/self/committed-events/{}",
                event.event_id
            )),
            StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::CAPABILITY_DENIED,
        )
        .await?;
        println!(
            "[agent-sidecar-pending] actual_accepted_add=1 actual_delivered_welcome=1 durable_local_state=1 consume_not_yet_sent=1 desired_not_effective=1 payload_refused=1"
        );
        let (grant, _) = controller
            .client
            .grant_realm_actions_to(
                accepted.event.realm_id.as_str(),
                agent.agent_did.as_str(),
                &["ak.message.create"],
            )
            .await?;
        let grant = arkret_wire::GrantId::new(grant)?;
        let write_only = self
            .actions
            .iter()
            .copied()
            .filter(|action| !matches!(*action, "ak.event.read" | "ak.object.read"))
            .collect::<Vec<_>>();
        let (write, claims) = content_direct_evidence::issue(
            self.deployment,
            agent,
            &write_only,
            &accepted.event.realm_id,
        )
        .await?;
        ensure!(
            claims
                .scopes
                .iter()
                .any(|action| action == "ak.message.create")
                && !claims.scopes.iter().any(|action| action == "ak.event.read")
        );
        ensure!(
            claims
                .scope_details
                .as_ref()
                .context("pending explicit write ceiling")?["capability_grant_refs"]
                == json!([grant])
        );
        let material = arkret_models_collaboration::mls_group_state_material::MlsMemberGroupStateMaterialReadRequestBody {
            realm_id:accepted.event.realm_id.clone(), effective_scope:accepted.event.scope_ref.clone(),
            mls_group_id:accepted.event.scope_ref.canonical_mls_group_id()?, epoch:Default::default(),
            group_state_event_id:self.genesis.event_id.clone(), caller_actor_id:ActorId::account(agent.agent_account.clone()),
            target_commit_event_ref:self.genesis.event_id.clone(),target_epoch:0,
            group_info_ref:arkret_wire::BlobRef::new(self.genesis.payload["group_info_ref"].as_str().context("accepted Genesis info")?)?,
            ratchet_tree_ref:arkret_wire::BlobRef::new(self.genesis.payload["ratchet_tree_ref"].as_str().context("accepted Genesis tree")?)?,max_response_bytes:None,
        };
        self.read
            .sdk()
            .self_mls_group_state_material(&material)
            .await?
            .validate_for_request(&material.as_peer_request())?;
        let (available, _) = crate::scenarios::mls_lifecycle_live::recipient_welcomes(self.read)
            .await
            .context("read-only actual Welcome control")?;
        ensure!(
            available.len() == 1
                && available[0].effective_scope == accepted.event.scope_ref
                && available[0].commit_event_ref == accepted.event.event_id
        );
        crate::harness::expect_api_error(
            write.get("/_arkret/self/device_messages"),
            StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::CAPABILITY_DENIED,
        )
        .await?;
        let (retained, _) = crate::scenarios::mls_lifecycle_live::recipient_welcomes(self.read)
            .await
            .context("read-only actual Welcome control")?;
        ensure!(
            retained == available,
            "denied Welcome read acknowledged or removed the queued original"
        );
        let (write_with_read, combined) = content_direct_evidence::issue(
            self.deployment,
            agent,
            self.actions,
            &accepted.event.realm_id,
        )
        .await?;
        ensure!(
            combined
                .scopes
                .iter()
                .any(|action| action == "ak.event.read")
                && combined
                    .scopes
                    .iter()
                    .any(|action| action == "ak.message.create")
        );
        ensure!(
            combined
                .scope_details
                .as_ref()
                .context("pending full content ceiling")?["capability_grant_refs"]
                == json!([grant])
        );
        let (pending_write, _) = agent_message(agent, agent_group, accepted, self.strand, &grant)?;
        {
            use std::io::Write;
            let mut file = std::fs::File::create(durable_state_path)?;
            file.write_all(&serde_json::to_vec(&agent_group.export_state_record()?)?)?;
            file.sync_all()?;
        }
        let durable: arkret::MlsGroupStateRecord =
            serde_json::from_slice(&std::fs::read(durable_state_path)?)?;
        *agent_group = arkret::ArkretMlsGroup::restore_from_state_record(&durable)?;
        ensure!(arkret_wire::ErrorCode::Conflict.http_status() == 409);
        crate::harness::expect_api_error(
            write_with_read
                .post("/_arkret/self/events")
                .canonical_json(&arkret_wire::EventAdmissionSubmission::new(
                    pending_write.clone(),
                ))?,
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::CONFLICT,
        )
        .await?;
        crate::harness::expect_api_error(
            controller.client.get(&format!(
                "/_arkret/self/committed-events/{}",
                pending_write.event_id
            )),
            StatusCode::NOT_FOUND,
            arkret_wire::ErrorCode::NOT_FOUND,
        )
        .await?;
        controller
            .client
            .revoke_realm_grant(accepted.event.realm_id.as_str(), grant.as_str())
            .await?;
        let still_pending = controller
            .client
            .sdk()
            .agent_sidecar_get(sidecar_id)
            .await?;
        ensure!(
            still_pending.desired_agent_ids == vec![agent.agent_account.principal_id.clone()]
                && still_pending.effective_agent_ids.is_empty()
        );
        println!(
            "[agent-sidecar-pending-grant] actual_write_only_ceiling=1 same_queued_welcome_read_positive=1 write_does_not_read_welcome=1 queued_original_retained=1 read_and_write_ceiling_for_payload=1 valid_agent_ciphertext_durable_before_attempt=1 effective_missing_write_refused=1 effective_conflict_409=1 no_committed_original=1 temporary_grant_revoked=1 roster_not_changed_by_grant=1"
        );
        Ok(())
    }
}

pub async fn run_agent_content_sidecar_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    let fixture = crate::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let contract = &fixture["session_content_authority_contract"];
    ensure!(
        arkret_canonical::sha256_hex(arkret_canonical::canonical_json_bytes(
            &contract["defaults"]
        )?) == "49fad7028393f37d28ca1a4ee06c376d6b16be0a16e4bfa35b77826a53130665"
    );
    let path = json!([{"kind":"sidecar_read","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":true}]);
    for (name, input, expected) in [
        (
            "sidecar_read_without_literal_grant",
            json!({"paths":path,"resource_profile":"sidecar"}),
            "allow",
        ),
        (
            "sidecar_read_does_not_grant_write",
            json!({"action":"ak.message.create","paths":[{"kind":"sidecar_read","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}],"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "bootstrap_desired_not_yet_effective",
            json!({"phase":"bootstrap","effective":false,"mls_ready":false,"paths":path,"resource_profile":"sidecar"}),
            "allow",
        ),
        (
            "bootstrap_wrong_endpoint",
            json!({"phase":"bootstrap","effective":false,"exact_endpoint":false,"paths":path,"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "bootstrap_missing_add_welcome_claim_lineage",
            json!({"phase":"bootstrap","accepted_lineage":false,"paths":path,"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "desired_cannot_read_payload",
            json!({"phase":"payload","effective":false,"paths":path,"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "effective_sidecar_payload",
            json!({"phase":"payload","paths":path,"resource_profile":"sidecar"}),
            "allow",
        ),
        (
            "issue_pending_mls_is_only_ceiling",
            json!({"mls_ready":false,"effective":false,"paths":path,"resource_profile":"sidecar"}),
            "allow",
        ),
        (
            "sidecar_explicit_write_grant",
            json!({"resource_profile":"sidecar","action":"ak.message.create","paths":[{"kind":"capability_grant","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}],"phase":"payload"}),
            "allow",
        ),
        (
            "sidecar_write_grant_after_desired_loss",
            json!({"resource_profile":"sidecar","action":"ak.message.create","paths":[{"kind":"capability_grant","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}],"phase":"payload","desired":false}),
            "deny",
        ),
        (
            "sidecar_write_grant_without_effective",
            json!({"resource_profile":"sidecar","action":"ak.message.create","paths":[{"kind":"capability_grant","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}],"phase":"payload","effective":false}),
            "deny",
        ),
        (
            "sidecar_material_not_a_write_grant_operation",
            json!({"resource_profile":"sidecar","action":"ak.message.create","paths":[{"kind":"capability_grant","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}],"phase":"bootstrap"}),
            "deny",
        ),
        (
            "queued_welcome_after_desired_revoke",
            json!({"phase":"bootstrap","desired":false,"paths":path,"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "future_epoch_material_after_desired_revoke",
            json!({"phase":"future_material","desired":false,"paths":path,"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "valid_future_epoch_material",
            json!({"phase":"future_material","paths":path,"resource_profile":"sidecar"}),
            "allow",
        ),
        (
            "wrong_sidecar_binding",
            json!({"phase":"payload","same_account_scope":false,"paths":path,"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "realm_grant_cannot_replace_sidecar_authority",
            json!({"resource_profile":"sidecar","paths":[{"kind":"capability_grant","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":true}]}),
            "deny",
        ),
    ] {
        let rows = contract["cases"]
            .as_array()
            .context("Sidecar contract")?
            .iter()
            .filter(|v| v["name"] == name)
            .collect::<Vec<_>>();
        ensure!(
            rows.len() == 1 && rows[0]["input"] == input && rows[0]["expected"] == expected,
            "review changed Sidecar case {name}"
        );
    }
    let deployment =
        coauth_session_evidence::actual_agent_deployment("agent-content-sidecar").await?;
    let client = &deployment.controller;
    let principal = client.principal.as_ref().context("actual controller")?;
    let controller = Member {
        client: client.clone(),
        account: deployment.account.clone(),
        actor: ActorId::account(deployment.account.clone()),
        device: principal.device_id.clone(),
        method: DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
            .map_err(anyhow::Error::msg)?,
        key: principal.device_signing_key.clone(),
        authorize_event_id: principal.founding_authorize_event_id.clone(),
    };
    let created = client
        .create_realm_with(
            json!({"title":"Real issuer Sidecar", "public":false,"join_rule":"public",
        "plaintext_visible_services":[deployment.station.service_id()]}),
        )
        .await?;
    let realm = RealmId::new(created["realm_id"].as_str().context("Sidecar parent")?)?;
    let strand = arkret_wire::StrandId::new(
        created["default_strand_id"]
            .as_str()
            .context("Sidecar context")?,
    )?;
    let generation = EventId::new(
        created["event_response"]["commits"]
            .as_array()
            .and_then(|v| v.last())
            .and_then(|v| v["event_ref"].as_str())
            .context("controller current generation")?,
    )?;
    client
        .grant_realm_actions_to(
            realm.as_str(),
            &client.actor,
            &["ak.event.read", "ak.message.create"],
        )
        .await?;
    let operations = arkret_schema::agent_runtime_scope::complete_agent_runtime_scope([
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1,
        ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
        ServiceOperationId::SELF_COMMITTED_EVENT_RESOURCE_GET_V1,
        ServiceOperationId::SELF_REALM_READ_STREAMS_V1,
        ServiceOperationId::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1,
        ServiceOperationId::SELF_REALM_STATE_SNAPSHOT_READ_BY_REF_V1,
        ServiceOperationId::SELF_MLS_READ_ROSTER_AUTHORITY_V1,
        ServiceOperationId::SELF_MLS_READ_GROUP_STATE_MATERIAL_V1,
        ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_READ_CLAIM_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
        ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
        ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK_V1,
        "ak.event.read",
        "ak.object.read",
        "ak.message.create",
    ])?;
    let actions = operations.iter().map(String::as_str).collect::<Vec<_>>();
    let mut provision_scope = requested_scope(&actions)?;
    provision_scope.resources.push(serde_json::from_value(
        json!({"kind":"realm","realm_id":realm}),
    )?);
    let mut agent = AgentRuntimeSession::establish_observed(
        &deployment.station,
        AgentSessionIssuer::Coauth {
            base: deployment.coauth.base_url(),
            database_url: &deployment.coauth.pg.connect_url,
        },
        client,
        &deployment.account,
        "actual-sidecar-agent",
        provision_scope,
        None,
    )
    .await?;
    let mut membership = MembershipPayload::join(
        realm.clone(),
        ActorId::account(agent.agent_account.clone()),
        "Private Sidecar membership",
    );
    membership.agent_controller_binding = Some(AgentControllerMembershipBinding {
        controller_account_id: deployment.account.clone(),
        controller_membership_generation_ref: generation,
        controller_terminal_event_ref: None,
    });
    let joined = client
        .author_event(realm.as_str(), "ak.member.state", membership.to_value()?)
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        client,
        &deployment.account,
        &client.device_id,
        &joined,
    )
    .await?;
    let selected = client
        .sdk()
        .agent_participation_replace(
            agent.agent_account.principal_id.as_str(),
            &arkret::ParticipationReplaceRequestBody {
                target_scope: arkret::ParticipationScope::Realm {
                    realm_id: realm.clone(),
                },
                selection: arkret::ParticipationBits {
                    reply_message: true,
                    ..arkret::ParticipationBits::NONE
                },
                expected_version: 0,
            },
        )
        .await?;
    ensure!(
        selected
            .agent_participation_entries
            .iter()
            .any(|row| row.scope
                == arkret::ParticipationScope::Realm {
                    realm_id: realm.clone()
                }
                && row.selection.reply_message
                && row.version == 1)
    );
    let operation = ProtocolOperationId::new(format!("ak:operation:{}", unique_uuid7()))
        .map_err(anyhow::Error::msg)?;
    let prepare = SidecarEnsureRequestBody::Prepare(SidecarEnsurePrepareRequestBody {
        phase: SidecarEnsurePreparePhase::Prepare,
        operation_id: operation.clone(),
        idempotency_key: IdempotencyKey::new(format!("sidecar-prepare-{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?,
        source_realm_id: realm.clone(),
        controller_account_id: deployment.account.clone(),
        context_ref: SidecarContextRef::Strand {
            strand_id: strand.clone(),
        },
    });
    let SidecarEnsureOutcome::PreparedNew(prepared) = client
        .sdk()
        .agent_sidecar_ensure(&client.verify_publication(prepare)?)
        .await?
    else {
        bail!("Sidecar new preparation required")
    };
    let create = client.sign_prepared_contact_event(
        &prepared.create_event_draft,
        arkret_wire::EventKind::SidecarCreate.as_str(),
    )?;
    let attach = client.sign_prepared_contact_event(
        &prepared.context_attach_event_draft,
        arkret_wire::EventKind::SidecarContextAttach.as_str(),
    )?;
    let request = SidecarEnsureRequestBody::Commit(SidecarEnsureCommitRequestBody {
        phase: SidecarEnsureCommitPhase::Commit,
        operation_id: operation,
        idempotency_key: IdempotencyKey::new(format!("sidecar-commit-{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?,
        reservation_handle: prepared.reservation_handle,
        create_event: create.clone(),
        context_attach_event: attach,
    });
    let SidecarEnsureOutcome::Accepted(accepted) = client
        .sdk()
        .agent_sidecar_ensure(&client.verify_publication(request.clone())?)
        .await?
    else {
        bail!("Sidecar acceptance required")
    };
    let sidecar = accepted.sidecar_id;
    ensure!(sidecar == arkret_wire::SidecarId::from_event_id(&create.event_id));
    let view = client.sdk().agent_sidecar_get(&sidecar).await?;
    ensure!(
        view.sidecar.id == sidecar
            && view.sidecar.realm_id == realm
            && view.sidecar.controller_account_id == deployment.account
    );
    ensure!(
        view.desired_agent_ids == vec![agent.agent_account.principal_id.clone()]
            && view.effective_agent_ids.is_empty()
            && view.mls_context.mls_group_id.is_none()
    );
    let read_actions = actions
        .iter()
        .copied()
        .filter(|v| *v != "ak.message.create")
        .collect::<Vec<_>>();
    let (read, claims) =
        content_direct_evidence::issue(&deployment, &agent, &read_actions, &realm).await?;
    ensure!(
        claims
            .scope_details
            .as_ref()
            .context("Sidecar frozen ceiling")?["capability_grant_refs"]
            == json!([])
    );
    ensure!(
        claims.scopes.iter().any(|v| v == "ak.event.read")
            && !claims.scopes.iter().any(|v| v == "ak.message.create")
    );
    agent.runtime = read.clone();
    let scope = ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let binding = arkret::MlsGovernanceBindingPayload::sidecar(
        realm.clone(),
        sidecar.clone(),
        None,
        0,
        0,
        0,
        view.mls_context.participant_authority_digest,
        view.mls_context.authority_stream_head,
    )?;
    let mut group = controller
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &binding)?;
    let leaf = crate::scenarios::cross_station_mls_welcome::genesis_creator_leaf_authority(
        &mut group,
        &controller,
    )?;
    let (info, tree) = group.public_group_state_bytes()?;
    let info = upload_public_blob(client, &realm, &info).await?;
    let tree = upload_public_blob(client, &realm, &tree).await?;
    let mut genesis = client.author_event(realm.as_str(), "ak.mls.genesis", json!({
        "cipher_suite":ACTIVE_SUITE,"group_info_ref":info,"ratchet_tree_ref":tree,"governance_binding":binding,"creator_leaf_authority":leaf,
        "created_at":arkret_canonical::format_timestamp_canonical(Utc::now())})).await?;
    genesis.scope_ref = scope.clone();
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut genesis,
        controller.key.to_bytes(),
    )?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        client,
        &deployment.account,
        &client.device_id,
        &genesis,
    )
    .await?;
    let observer = PendingPayload {
        read: &read,
        strand: &strand,
        deployment: &deployment,
        actions: &actions,
        genesis: &genesis,
    };
    let (state, mut agent_group) = Box::pin(private_reply::join_agent_with_observer(
        &controller,
        &agent,
        &mut group,
        &genesis,
        Some(&observer),
    ))
    .await?;
    let (_, narrowed) =
        content_direct_evidence::issue(&deployment, &agent, &actions, &realm).await?;
    ensure!(
        narrowed
            .scopes
            .iter()
            .any(|action| action == "ak.event.read")
            && !narrowed
                .scopes
                .iter()
                .any(|action| action == "ak.message.create"),
        "Sidecar read produced write authority: {:?}",
        narrowed.scopes
    );
    ensure!(
        narrowed
            .scope_details
            .as_ref()
            .context("narrowed ceiling")?["capability_grant_refs"]
            == json!([])
    );
    let (message, plaintext) = controller_message(&controller, &mut group, &state, &strand).await?;
    let (fresh_read, fresh_claims) =
        content_direct_evidence::issue(&deployment, &agent, &read_actions, &realm).await?;
    ensure!(
        fresh_claims
            .scope_details
            .as_ref()
            .context("effective Sidecar ceiling")?["capability_grant_refs"]
            == json!([])
    );
    let received = fresh_read
        .sdk()
        .committed_event_get(&message.event_id)
        .await?;
    ensure!(received.reducer_input() == Some(&message));
    let envelope: arkret::EncryptedEnvelope =
        serde_json::from_value(message.payload["encrypted_content"].clone())?;
    let domain = arkret::mls_basic_credential_identity(message.actual_signer())?;
    let header = envelope.reconstruct_pre_encryption_header(
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope,
        message.kind.as_str(),
        std::str::from_utf8(&domain)?,
        None,
    )?;
    let payload =
        arkret::mls::encrypted_envelope_to_payload_with_verified_header(&envelope, header)?;
    ensure!(agent_group.decrypt_payload(&payload)? == plaintext);
    println!(
        "[agent-sidecar-content] actual_coauth=1 no_literal_read_or_write_grant=1 issued_before_mls_ready=1 accepted_add_welcome_claim=1 durable_before_consume=1 pending_payload_refused=1 effective_payload_full_and_decrypted=1 mixed_request_read_only_ceiling=1"
    );
    let (grant, _) = client
        .grant_realm_actions_to(
            realm.as_str(),
            agent.agent_did.as_str(),
            &["ak.message.create"],
        )
        .await?;
    let grant = arkret_wire::GrantId::new(grant)?;
    let grant_event = EventId::from_token_bytes(grant.token_bytes())?;
    let original_grant = client.sdk().committed_event_get(&grant_event).await?;
    let grant_payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(serde_json::to_value(
            &original_grant
                .reducer_input()
                .context("accepted Sidecar write grant")?
                .payload,
        )?)?;
    ensure!(matches!(grant_payload.grant.subject,
        arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(ref actor)
        if actor == &ActorId::account(agent.agent_account.clone())));
    let (write, write_claims) =
        content_direct_evidence::issue(&deployment, &agent, &actions, &realm).await?;
    ensure!(
        write_claims
            .scopes
            .iter()
            .any(|action| action == "ak.message.create")
    );
    ensure!(
        write_claims
            .scope_details
            .as_ref()
            .context("explicit write ceiling")?["capability_grant_refs"]
            == json!([grant])
    );
    let (reply, reply_plaintext) =
        agent_message(&agent, &mut agent_group, &state, &strand, &grant)?;
    let outcome: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            write
                .post("/_arkret/self/events")
                .canonical_json(&arkret_wire::EventAdmissionSubmission::new(reply.clone()))?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(&outcome, AuthoritySubmitOutcome::Accepted {status:AuthorityCommitStatus::Committed,commit}
        if commit.event_ref == reply.event_id && commit.stream_ref == state.commit.stream_ref),
        "Sidecar granted write did not commit: {outcome:?}"
    );
    ensure!(
        client
            .sdk()
            .committed_event_get(&reply.event_id)
            .await?
            .reducer_input()
            == Some(&reply)
    );
    ensure!(open_message(&mut group, &reply)? == reply_plaintext);
    let future_state = advance_epoch_material(
        &controller,
        &agent,
        &fresh_read,
        &mut group,
        &mut agent_group,
        &state.event.scope_ref,
    )
    .await?;
    let (future_message, future_plaintext) =
        controller_message(&controller, &mut group, &future_state, &strand).await?;
    ensure!(
        fresh_read
            .sdk()
            .committed_event_get(&future_message.event_id)
            .await?
            .reducer_input()
            == Some(&future_message)
    );
    ensure!(open_message(&mut agent_group, &future_message)? == future_plaintext);
    other_controller_content(
        &deployment,
        &agent,
        &fresh_read,
        &realm,
        &strand,
        &future_message,
    )
    .await?;
    let (queued_before_loss, _) =
        crate::scenarios::mls_lifecycle_live::recipient_welcomes(&fresh_read).await?;
    ensure!(
        queued_before_loss.len() == 1
            && queued_before_loss[0].commit_event_ref == state.event.event_id
            && queued_before_loss[0].effective_scope == state.event.scope_ref,
        "the accepted Welcome must still be queued without ACK after consume"
    );
    let set = arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload {
        agent_account_id: agent.agent_account.clone(),
        controller_account_id: deployment.account.clone(),
        interaction_mode:
            arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public,
        expected_revision: None,
    };
    let change = client
        .author_event(
            realm.as_str(),
            "ak.agent.interaction.set",
            serde_json::to_value(set)?,
        )
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        client,
        &deployment.account,
        &client.device_id,
        &change,
    )
    .await?;
    let retained = client.sdk().agent_sidecar_get(&sidecar).await?;
    ensure!(
        retained.desired_agent_ids == vec![agent.agent_account.principal_id.clone()]
            && retained.effective_agent_ids == vec![agent.agent_account.principal_id.clone()],
        "mode changed Sidecar roster: desired={:?} effective={:?}",
        retained.desired_agent_ids,
        retained.effective_agent_ids
    );
    let leave = MembershipPayload::transition(
        arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Leave,
        ActorId::account(agent.agent_account.clone()),
        "Revoke exact Sidecar membership source",
    );
    let leave = client
        .author_event(realm.as_str(), "ak.member.state", leave.to_value()?)
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        client,
        &deployment.account,
        &client.device_id,
        &leave,
    )
    .await?;
    let revoked = client.sdk().agent_sidecar_get(&sidecar).await?;
    ensure!(revoked.desired_agent_ids.is_empty() && revoked.effective_agent_ids.is_empty());
    let (denied, _) = agent_message(&agent, &mut agent_group, &future_state, &strand, &grant)?;
    let submit = ServiceOperationId::from_wire(ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1)
        .context("registered self events operation")?;
    ensure!(
        submit
            .operation_specific_errors()
            .iter()
            .any(|entry| matches!(
                entry,
                arkret_wire::OperationSpecificError::Code(
                    arkret_wire::ErrorCode::FailedPrecondition
                )
            ))
    );
    ensure!(arkret_wire::ErrorCode::FailedPrecondition.http_status() == 409);
    ensure!(
        arkret_wire::ReasonCode::from_wire(arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED)
            .descriptor()
            .is_some()
    );
    let rejected = crate::harness::expect_api_error(
        write
            .post("/_arkret/self/events")
            .canonical_json(&arkret_wire::EventAdmissionSubmission::new(denied.clone()))?,
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
    )
    .await?;
    ensure!(
        rejected
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str)
            == Some(arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED)
    );
    crate::harness::expect_api_error(
        client.get(&format!(
            "/_arkret/self/committed-events/{}",
            denied.event_id
        )),
        StatusCode::NOT_FOUND,
        arkret_wire::ErrorCode::NOT_FOUND,
    )
    .await?;
    ensure!(client.sdk().committed_event_get(&grant_event).await? == original_grant);
    crate::harness::expect_api_error(
        fresh_read.get("/_arkret/self/device_messages"),
        StatusCode::FORBIDDEN,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
    )
    .await?;
    crate::harness::expect_api_error(
        fresh_read.get(&format!(
            "/_arkret/self/committed-events/{}",
            future_state.event.event_id
        )),
        StatusCode::NOT_FOUND,
        arkret_wire::ErrorCode::NOT_FOUND,
    )
    .await?;
    ensure!(
        client
            .sdk()
            .committed_event_get(&future_state.event.event_id)
            .await?
            .reducer_input()
            == Some(&future_state.event)
    );
    println!(
        "[agent-sidecar-future] actual_governed_update_epoch_two=1 accepted_lineage_read=1 current_effective_endpoint=1 update_installed_and_durable=1 new_epoch_message_decrypted=1 accepted_desired_loss=1 old_read_ceiling_retained=1 update_material_new_delivery_denied=1 controller_original_retained=1 prior_knowledge_not_retracted=1"
    );
    println!(
        "[agent-sidecar-revoked-welcome] actual_unacked_welcome_present_after_consume=1 exact_scope_and_add=1 accepted_membership_loss=1 old_read_ceiling_retained=1 queued_welcome_new_delivery_denied=1 no_retroactive_knowledge_claim=1"
    );
    println!(
        "[agent-sidecar-write] accepted_original_grant=1 fresh_real_coauth_write_ceiling=1 explicit_agent_message_committed=1 controller_decrypted=1 accepted_private_to_public=1 mode_preserves_roster=1 accepted_agent_leave=1 desired_and_effective_lost=1 old_write_credential_refused=1 required_rotation_checkpoint_denied=1 rejected_event_not_stored=1 grant_original_retained=1"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: REVIEWED_SIDECAR_CONTENT_CASES
            .iter()
            .map(|name| crate::conformance::CaseExecutionResult {
                case_id: (*name).to_owned(),
                assertions: 1,
            })
            .collect(),
    })
}
