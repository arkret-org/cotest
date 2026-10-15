//! The accepted owned Direct's actual MLS bootstrap, durable Agent and binding.

use arkret::{ArkretMlsGroup, MlsGovernanceBindingPayload};
use arkret_models_collaboration::direct_conversation::{
    DirectConversationResolveOutcome, DirectConversationResolveRequestBody,
};

use super::*;

pub(super) struct Joined {
    pub realm: RealmId,
    pub state_ref: EventId,
    pub controller: ArkretMlsGroup,
    pub agent: ArkretMlsGroup,
}

fn authored(
    controller: &TestActorClient,
    account: &AccountId,
    kind: &str,
    scope: ScopeRef,
    payload: serde_json::Value,
    created_at: chrono::DateTime<Utc>,
    bootstrap: Option<&EventId>,
) -> Result<Event> {
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
    let mut event = arkret_wire::test_support::raw_event_at(
        kind,
        scope,
        account.principal_id.clone(),
        account.station_id.clone(),
        payload,
        created_at,
    )?;
    if let Some(reference) = bootstrap {
        event.authorization_ref = Some(
            arkret_wire::AuthorizationRef::new(
                "ak.authority.direct_conversation_bootstrap_participant.v1".to_owned(),
            )
            .map_err(anyhow::Error::msg)?,
        );
        event.semantic_refs.push(arkret_wire::SemanticRef::new(
            reference.to_string(),
            "direct_conversation_founding_unit",
        ));
    }
    Ok(arkret_test_kit::sign_verifiable_event(
        event,
        &signer,
        arkret::canonical::DigestSuite::Sha256,
    )?
    .expect_verifiable())
}

async fn submit(controller: &TestActorClient, event: &Event) -> Result<()> {
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
    ensure!(
        matches!(outcome, AuthoritySubmitOutcome::Accepted { status: AuthorityCommitStatus::Committed, commit } if commit.event_ref == event.event_id)
    );
    Ok(())
}

async fn blob(controller: &TestActorClient, bytes: &[u8]) -> Result<arkret_wire::BlobRef> {
    let value = expect_json(
        controller.post("/_arkret/self/blob/upload").multipart(
            crate::scenarios::delivery_media::blob_upload_form(bytes, "application/octet-stream")?,
        ),
        StatusCode::OK,
    )
    .await?;
    Ok(arkret_wire::BlobRef::new(
        value["blob_ref"]
            .as_str()
            .context("unbound public MLS Blob")?,
    )?)
}

pub(super) async fn join(
    material: &terminal_evidence::Materials<'_>,
    runtime: &TestActorClient,
    founded: direct_evidence::Founded,
) -> Result<Joined> {
    let realm = founded.coordinates.realm_id.clone();
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let principal = material
        .controller
        .principal
        .as_ref()
        .context("accepted controller")?;
    let method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    let identity = ArkretMlsIdentity::new_human_device(
        ActorId::account(material.agent.controller_account.clone()),
        principal.device_id.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(principal.device_signing_key.clone()),
    )?;
    let genesis_binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut controller = identity.create_group_with_governance_binding(&scope, &genesis_binding)?;
    controller.install_local_creator_binding(
        ActorId::account(material.agent.controller_account.clone()),
        Some(principal.founding_authorize_event_id.clone()),
    )?;
    let leaves = controller.verified_leaf_bindings()?;
    let [creator] = leaves.as_slice() else {
        bail!("Direct Genesis requires one controller leaf");
    };
    let creator_authority =
        arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority {
            leaf_signature_key_b64u: creator.signature_key.clone(),
            endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                device_id: principal.device_id.clone(),
            },
            authorization_event_ref: principal.founding_authorize_event_id.clone(),
        };
    let (info, tree) = controller.public_group_state_bytes()?;
    let info_ref = blob(material.controller, &info).await?;
    let tree_ref = blob(material.controller, &tree).await?;
    let created_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let genesis = authored(
        material.controller,
        &material.agent.controller_account,
        "ak.mls.genesis",
        scope.clone(),
        json!({
            "cipher_suite": crate::scenarios::mls_lifecycle_live::ACTIVE_SUITE,
            "group_info_ref": info_ref, "ratchet_tree_ref": tree_ref,
            "creator_leaf_authority": creator_authority, "governance_binding": genesis_binding,
            "created_at": arkret_canonical::format_timestamp_canonical(created_at),
        }),
        created_at,
        None,
    )?;
    submit(material.controller, &genesis).await?;
    let agent_identity = ArkretMlsIdentity::new_agent(
        ActorId::account(material.agent.agent_account.clone()),
        material.agent.verification_method.clone(),
        material.agent.key_authorization.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(material.agent.runtime_key.clone()),
    )?;
    let package = agent_identity.key_package_record()?;
    let private = tempfile::NamedTempFile::new()?;
    std::fs::write(private.path(), agent_identity.export_private_state()?)?;
    private.as_file().sync_all()?;
    let upload = agent_identity.signed_key_packages_upload_request(
        std::slice::from_ref(&package),
        material.agent.verification_method.as_str(),
    )?;
    runtime.sdk().keypackages_upload(&upload).await?;
    let mut request = material.claim.clone();
    request.intended_realm_id = realm.clone();
    request.mls_group_id = scope.canonical_mls_group_id()?;
    request.claim_request_id = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(&arkret_canonical::sha256_bytes(unique_uuid7().as_bytes())[..16]),
    )
    .map_err(anyhow::Error::msg)?;
    request.target_keypackage_ref = Some(serde_json::from_value(serde_json::to_value(
        &package.keypackage_ref,
    )?)?);
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signed_at, .. } =
        &mut request.requester_authorization
    else {
        bail!("Direct claim needs controller device");
    };
    *signed_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let signed = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &request.unsigned_request(),
        &request.service_binding,
        &request.requester_authorization,
    )?;
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut request.requester_authorization
    else {
        unreachable!()
    };
    signature.sig = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(principal.device_signing_key.sign(&signed).to_bytes()),
    )
    .map_err(anyhow::Error::msg)?;
    let claims: arkret_models_crypto::KeyPackagesClaimOutcome = serde_json::from_value(
        expect_json(
            material
                .controller
                .post("/_arkret/self/keys/keypackages/claim")
                .header("Content-Type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(&request)?),
            StatusCode::OK,
        )
        .await?,
    )?;
    let [claim] = claims.claims.as_slice() else {
        bail!("Direct claim did not select one Agent package");
    };
    let resolution = runtime
        .sdk()
        .open_service_resolution(material.station.service_id())
        .await?;
    arkret::verify_peer_keypackage_claim_receipt_signature(&claims.claim_receipt, &resolution)?;
    let binding =
        MlsGovernanceBindingPayload::new(scope.clone(), Some(genesis.event_id.clone()), 0, 1, 0)?;
    let add = controller.add_member_with_governance_binding(
        &arkret::mls_key_package_record_from_claim(claim)?,
        &binding,
    )?;
    let commit = authored(
        material.controller,
        &material.agent.controller_account,
        "ak.mls.commit",
        scope.clone(),
        serde_json::to_value(arkret::MlsCommitPayload::new(
            genesis.event_id.clone(),
            0,
            &add.commit,
            binding,
        )?)?,
        Utc::now(),
        Some(&founded.create_ref),
    )?;
    let mut welcome = arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new_v7_at(u64::try_from(
            Utc::now().timestamp_millis(),
        )?),
        realm_id: realm.clone(),
        effective_scope: scope.clone(),
        commit_event_ref: commit.event_id.clone(),
        recipient_actor_id: ActorId::account(material.agent.agent_account.clone()),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method: material.agent.verification_method.clone(),
        },
        keypackage_claim_ref: add.welcome.keypackage_claim_ref.clone(),
        ciphertext_b64: add.welcome.ciphertext_b64.clone(),
        producer_proof: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: method.clone(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: Utc::now(),
            sig: arkret_wire::Base64UrlString::new("AA".to_owned()).map_err(anyhow::Error::msg)?,
        },
    };
    let mut unsigned = serde_json::to_value(&welcome)?;
    unsigned
        .as_object_mut()
        .context("Welcome object")?
        .remove("producer_proof");
    welcome.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        method.clone(),
        arkret_canonical::normalize_timestamp_canonical(Utc::now()),
        &principal.device_signing_key,
    )?;
    let submission = arkret_wire::MlsCommitSubmission {
        commit_event: commit.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(unique_uuid7().parse()?)?,
    };
    let outcome: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            material
                .controller
                .post("/_arkret/self/events")
                .header("Content-Type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(&submission)?),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(&outcome, AuthoritySubmitOutcome::Accepted { status: AuthorityCommitStatus::Committed, commit: accepted } if accepted.event_ref == commit.event_id),
        "owned Direct MLS Add was not accepted: {outcome:?}"
    );
    let accepted = crate::scenarios::mls_lifecycle_live::accepted_full_view(
        material.controller,
        &commit.event_id,
    )
    .await?;
    let base = arkret_wire::MlsGroupCurrent {
        effective_scope: scope.clone(),
        genesis_event_ref: genesis.event_id.clone(),
        cipher_suite: NonEmptyString::new("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
            .map_err(anyhow::Error::msg)?,
        current_mls_commit_event_ref: genesis.event_id.clone(),
        epoch: 0,
        current_key_access_revision: 0,
        covered_key_access_revision: 0,
        public_tree_ref: tree_ref,
    };
    controller.install_accepted_commit(&accepted, &base)?;
    let (queued, ack_token) =
        crate::scenarios::mls_lifecycle_live::recipient_welcomes(runtime).await?;
    ensure!(queued.contains(&welcome));
    let own_claims = runtime
        .sdk()
        .keypackages_claim_query(&arkret_models_crypto::KeyPackagesClaimQueryRequestBody {
            claim_id: arkret_wire::KeypackageClaimId::new(claim.claim_id.clone())?,
        })
        .await?;
    garth::mls::verify_welcome_claim(
        &welcome,
        &garth::mls::LocalMlsEndpoint::agent_runtime(
            realm.clone(),
            ActorId::account(material.agent.agent_account.clone()),
            material.agent.verification_method.clone(),
        ),
        &accepted.event,
        &own_claims,
        material.station.service_id(),
        &material.agent.key_authorization,
    )?;
    let restored = ArkretMlsIdentity::restore_from_private_state(
        ActorId::account(material.agent.agent_account.clone()),
        MlsEndpointIdentity::agent_runtime(
            material.agent.agent_account.principal_id.clone(),
            material.agent.verification_method.clone(),
            material.agent.key_authorization.clone(),
        )?,
        &std::fs::read(private.path())?,
    )?;
    let mut agent =
        ArkretMlsGroup::join_from_verified_welcome_delivery(restored, &welcome, &accepted)?;
    let roster = arkret::MlsMemberRosterAuthorityReadRequestBody {
        realm_id: realm.clone(),
        effective_scope: scope.clone(),
        mls_group_id: scope.canonical_mls_group_id()?,
        target_commit_event_ref: commit.event_id.clone(),
        target_epoch: 1,
        caller_actor_id: ActorId::account(material.agent.agent_account.clone()),
        cursor: None,
    };
    let page = runtime.sdk().self_mls_roster_authority(&roster).await?;
    ensure!(page.roster.next_cursor.is_none() && page.roster.records.len() == 2);
    let peer =
        arkret::verify_mls_member_roster_authority_pages(std::slice::from_ref(&page), &roster)?;
    let public = runtime
        .sdk()
        .self_mls_group_state_material(&arkret::mls_roster_genesis_material_request(
            &peer,
            &page.roster.manifest,
        ))
        .await?;
    arkret::install_verified_mls_self_roster_bindings(&mut agent, &[page], &roster, &public)
        .map_err(anyhow::Error::msg)?;
    let mut controller_roster = roster.clone();
    controller_roster.caller_actor_id = ActorId::account(material.agent.controller_account.clone());
    let controller_page = material
        .controller
        .sdk()
        .self_mls_roster_authority(&controller_roster)
        .await?;
    let peer = arkret::verify_mls_member_roster_authority_pages(
        std::slice::from_ref(&controller_page),
        &controller_roster,
    )?;
    let public = material
        .controller
        .sdk()
        .self_mls_group_state_material(&arkret::mls_roster_genesis_material_request(
            &peer,
            &controller_page.roster.manifest,
        ))
        .await?;
    arkret::install_verified_mls_self_roster_bindings(
        &mut controller,
        &[controller_page],
        &controller_roster,
        &public,
    )
    .map_err(anyhow::Error::msg)?;
    let directory = tempfile::tempdir()?;
    agent = persist_and_reopen_agent_welcome(
        &agent,
        &welcome,
        &own_claims,
        &directory.path().join("welcome"),
    )?;
    let receipt = agent.identity().sign_recipient_mls_durable_receipt(
        arkret_models_crypto::RecipientMlsDurableReceipt {
            domain: NonEmptyString::new(
                arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1.to_owned(),
            )
            .map_err(anyhow::Error::msg)?,
            claim_request_id: request.claim_request_id.clone(),
            key_package_ref: NonEmptyString::new(claim.keypackage_ref.clone())
                .map_err(anyhow::Error::msg)?,
            recipient: arkret_models_crypto::RecipientMlsDurableSigner::Agent {
                recipient_agent_id: material.agent.agent_account.principal_id.clone(),
                recipient_agent_verification_method: material.agent.verification_method.clone(),
                agent_key_authorize_event_id: material.agent.key_authorization.clone(),
            },
            recipient_id: material.station.service_id().clone(),
            realm_id: realm.clone(),
            mls_group_id: request.mls_group_id.clone(),
            mls_epoch: 1,
            welcome_ref: welcome.welcome_id.clone(),
            welcome_digest: welcome.durable_receipt_digest()?,
            durable_at: Utc::now(),
            signature: arkret_models_crypto::KeyOperationSignature {
                kid: NonEmptyString::new(material.agent.verification_method.to_string())
                    .map_err(anyhow::Error::msg)?,
                signature_algorithm: None,
                sig: arkret_wire::Base64UrlString::new("AA".to_owned())
                    .map_err(anyhow::Error::msg)?,
            },
        },
    )?;
    let consume = agent.identity().signed_key_packages_consume_request(
        arkret_wire::KeypackageClaimId::new(claim.claim_id.clone())?,
        receipt,
    )?;
    let consume = persist_and_reopen_agent_consume(&consume, &directory.path().join("consume"))?;
    runtime.sdk().keypackages_consume(&consume).await?;
    runtime
        .post("/_arkret/self/device_messages/ack")
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &arkret_models_collaboration::device_messages::DeviceMessagesAckRequestBody {
                ack_token,
            },
        )?)
        .send()
        .await?
        .error_for_status()?;
    let payload = arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBoundPayload {
        pair_key: founded.coordinates.pair_key, unordered_participant_ids: vec![ActorId::account(material.agent.controller_account.clone()), ActorId::account(material.agent.agent_account.clone())], realm_id: realm.clone(), main_strand_id: founded.coordinates.main_strand_id, founding_unit_digest: founded.plan.founding_unit_digest, authorization_basis: founded.authorization_basis, initial_exact_pair_group_state_ref: commit.event_id.clone(), created_at: arkret_canonical::normalize_timestamp_canonical(Utc::now()),
    };
    let controller_bound = authored(
        material.controller,
        &material.agent.controller_account,
        "ak.direct_conversation.bound",
        scope.clone(),
        serde_json::to_value(&payload)?,
        Utc::now(),
        Some(&founded.create_ref),
    )?;
    submit(material.controller, &controller_bound).await?;
    let mut agent_bound = material.agent.author_scoped_event(
        arkret_wire::EventKind::DirectConversationBound,
        scope,
        serde_json::to_value(&payload)?,
        vec![arkret_wire::SemanticRef::new(
            founded.create_ref.to_string(),
            "direct_conversation_founding_unit",
        )],
    )?;
    agent_bound.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(
            "ak.authority.direct_conversation_bootstrap_participant.v1".to_owned(),
        )
        .map_err(anyhow::Error::msg)?,
    );
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut agent_bound,
        material.agent.runtime_key.to_bytes(),
    )?;
    submit(runtime, &agent_bound).await?;
    let result = material
        .controller
        .sdk()
        .direct_conversation_resolve(&DirectConversationResolveRequestBody {
            peer: arkret_models_collaboration::contact_operations::ContactPeer::Agent {
                actor_id: ActorId::account(material.agent.agent_account.clone()),
                controller_account_id: material.agent.controller_account.clone(),
            },
        })
        .await?;
    ensure!(
        matches!(result, DirectConversationResolveOutcome::Found { group_state_ref, .. } if group_state_ref == commit.event_id)
    );
    println!(
        "[agent-direct-mls] actual_genesis_add_welcome=1 verified_complete_roster=1 durable_private_reopen=1 actual_claim_consume=1 two_signed_binding_endorsements=1 resolver_found=1"
    );
    Ok(Joined {
        realm,
        state_ref: commit.event_id,
        controller,
        agent,
    })
}
