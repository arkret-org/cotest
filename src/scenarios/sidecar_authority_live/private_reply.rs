//! A real runtime leaf admitted into an accepted Realm or native Sidecar group.

use anyhow::{Context, Result, ensure};
use arkret_wire::ScopeRef;
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use serde_json::json;

use super::*;
use crate::scenarios::agent_runtime_live::AgentRuntimeSession;
use crate::scenarios::mls_lifecycle_live::{accepted_full_view, post_json, recipient_welcomes};

#[async_trait::async_trait(?Send)]
pub(crate) trait JoinObserver {
    async fn before_submission(
        &self,
        _controller: &Member,
        _agent: &AgentRuntimeSession,
        _submission: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody,
        _claim_request: &arkret_models_crypto::KeyPackagesClaimRequestBody,
    ) -> Result<()> {
        Ok(())
    }

    async fn before_consume(
        &self,
        controller: &Member,
        agent: &AgentRuntimeSession,
        controller_group: &mut arkret::ArkretMlsGroup,
        agent_group: &mut arkret::ArkretMlsGroup,
        accepted: &arkret_wire::CommittedEventFullView,
        durable_state_path: &std::path::Path,
    ) -> Result<()>;
}

pub(crate) async fn join_agent(
    controller: &Member,
    agent: &AgentRuntimeSession,
    group: &mut arkret::ArkretMlsGroup,
    genesis: &arkret_wire::Event,
) -> Result<(arkret_wire::CommittedEventFullView, arkret::ArkretMlsGroup)> {
    join_agent_with_observer(controller, agent, group, genesis, None).await
}

pub(crate) async fn join_agent_with_observer(
    controller: &Member,
    agent: &AgentRuntimeSession,
    group: &mut arkret::ArkretMlsGroup,
    genesis: &arkret_wire::Event,
    observer: Option<&dyn JoinObserver>,
) -> Result<(arkret_wire::CommittedEventFullView, arkret::ArkretMlsGroup)> {
    let scope = &genesis.scope_ref;
    let realm = scope.realm_id();
    let sidecar_id = match scope {
        ScopeRef::Sidecar { sidecar_id, .. } => Some(sidecar_id),
        ScopeRef::Realm { .. } => None,
        _ => anyhow::bail!("Realm or native Sidecar required"),
    };
    let identity = arkret::ArkretMlsIdentity::new_agent(
        arkret_wire::ActorId::account(agent.agent_account.clone()),
        agent.verification_method.clone(),
        agent.key_authorization.clone(),
        arkret::ArkretMlsSigner::from_ed25519_signing_key(agent.runtime_key.clone()),
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
            .await
            .context("private runtime KeyPackage upload")?
            .accepted
            == 1
    );
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut claim: arkret_models_crypto::KeyPackagesClaimRequestBody = serde_json::from_value(
        json!({
            "claim_request_id":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([47u8;16]),
            "target_agent_id":agent.agent_account.principal_id,
            "target_agent_verification_method":agent.verification_method,
            "target_agent_key_authorize_event_id":agent.key_authorization,
            "target_keypackage_ref":package.keypackage_ref,
            "requester_account_id":controller.account,"intended_realm_id":realm,
            "mls_group_id":scope.canonical_mls_group_id()?,"claim_purpose":"realm_membership",
            "required_capabilities":["ak.content.v1"],
            "expires_at":arkret_canonical::format_timestamp_canonical(now+chrono::Duration::minutes(4)),
            "service_binding":{"source_id":controller.account.station_id,"destination_id":agent.agent_account.station_id},
            "requester_authorization":{"kind":"device","verification_method":controller.method,
                "requester_device_id":controller.device,"device_authorize_event_id":controller.authorize_event_id,
                "signed_at":arkret_canonical::format_timestamp_canonical(now),
                "signature":{"kid":controller.method,"signature_algorithm":"Ed25519","signature":"AA"}}
        }),
    )?;
    let bytes = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &claim.unsigned_request(),
        &claim.service_binding,
        &claim.requester_authorization,
    )?;
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut claim.requester_authorization
    else {
        unreachable!()
    };
    signature.signature = arkret_wire::Base64UrlString::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(controller.key.sign(&bytes).to_bytes()),
    )
    .map_err(anyhow::Error::msg)?;
    let claimed = controller.client.sdk().keypackages_claim(&claim).await?;
    ensure!(claimed.claims.len() == 1);
    let resolution = controller
        .client
        .sdk()
        .open_service_resolution(&controller.account.station_id)
        .await?;
    arkret::verify_peer_keypackage_claim_receipt_signature(&claimed.claim_receipt, &resolution)?;
    let selected = &claimed.claims[0];
    ensure!(selected.agent_key_authorize_event_id.as_ref() == Some(&agent.key_authorization));
    let snapshot = controller
        .client
        .sdk()
        .realm_state_snapshot_head(realm)
        .await?;
    let base: arkret_wire::MlsGroupValue = snapshot
        .current_state_entries
        .iter()
        .find_map(|row| {
            let arkret_wire::CurrentState::Value {
                selector: arkret_wire::CurrentSelector::MlsGroup { scope_ref },
                value,
                ..
            } = row
            else {
                return None;
            };
            (scope_ref == scope).then(|| serde_json::from_value(value.clone()))
        })
        .context("Sidecar MLS current unavailable")??;
    let binding = if let Some(sidecar_id) = sidecar_id {
        let view = controller
            .client
            .sdk()
            .agent_sidecar_get(sidecar_id)
            .await?;
        arkret::MlsGovernanceBindingPayload::sidecar(
            realm.clone(),
            sidecar_id.clone(),
            Some(genesis.event_id.clone()),
            0,
            1,
            base.current_key_access_revision,
            view.mls_context.participant_authority_digest,
            view.mls_context.authority_stream_head,
        )?
    } else {
        arkret::MlsGovernanceBindingPayload::new(
            scope.clone(),
            Some(genesis.event_id.clone()),
            0,
            1,
            base.current_key_access_revision,
        )?
    };
    let add = group.add_member_with_governance_binding(
        &arkret::mls_key_package_record_from_claim(selected)?,
        &binding,
    )?;
    let payload = arkret::MlsCommitPayload::new(genesis.event_id.clone(), 0, &add.commit, binding)?;
    let mut event = controller
        .client
        .author_event(
            realm.as_str(),
            EventKind::MlsCommit.as_str(),
            canonical(serde_json::to_value(payload)?)?,
        )
        .await?;
    event.scope_ref = scope.clone();
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut event,
        controller.key.to_bytes(),
    )?;
    let mut welcome = arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new_v7_at(
            chrono::Utc::now().timestamp_millis() as u64,
        ),
        realm_id: realm.clone(),
        effective_scope: scope.clone(),
        commit_event_ref: event.event_id.clone(),
        recipient_actor_id: arkret_wire::ActorId::account(agent.agent_account.clone()),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method: agent.verification_method.clone(),
        },
        keypackage_claim_ref: add.welcome.keypackage_claim_ref,
        ciphertext_base64url: add.welcome.ciphertext_base64url,
        producer_proof: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: controller.method.clone(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: now,
            signature: arkret_wire::Base64UrlString::new("AA").map_err(anyhow::Error::msg)?,
        },
    };
    let mut unsigned = serde_json::to_value(&welcome)?;
    unsigned.as_object_mut().unwrap().remove("producer_proof");
    welcome.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        controller.method.clone(),
        now,
        &controller.key,
    )?;
    let submission =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::MlsCommit(
            arkret_wire::MlsCommitSubmission {
                commit_event: event.clone(),
                welcomes: vec![welcome.clone()],
                idempotency_key: arkret_wire::UuidV7::new(
                    crate::scenarios::mls_lifecycle_live::fresh_uuid_v7().parse()?,
                )?,
            },
        );
    if let Some(observer) = observer {
        observer
            .before_submission(controller, agent, &submission, &claim)
            .await?;
    }
    let (status, result) = post_json(&controller.client, &submission).await?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "Sidecar Add refused: {status} {result}"
    );
    let accepted = accepted_full_view(&controller.client, &event.event_id).await?;
    ensure!(group.install_accepted_commit(&accepted, &base)? == 1);
    let (queued, _ack) = recipient_welcomes(&agent.runtime)
        .await
        .context("private runtime Welcome queue")?;
    ensure!(queued == vec![welcome.clone()]);
    let queried = agent
        .runtime
        .sdk()
        .keypackages_claim_query(&arkret_models_crypto::KeyPackagesClaimQueryRequestBody {
            claim_id: arkret_wire::KeypackageClaimId::new(selected.claim_id.clone())?,
        })
        .await
        .context("private runtime claim receipt query")?;
    arkret::verify_peer_keypackage_claim_receipt_signature(&queried.claim_receipt, &resolution)?;
    let endpoint = garth::mls::LocalMlsEndpoint::agent_runtime(
        realm.clone(),
        arkret_wire::ActorId::account(agent.agent_account.clone()),
        agent.verification_method.clone(),
    );
    garth::mls::verify_welcome_claim(
        &welcome,
        &endpoint,
        &accepted.event,
        &queried,
        &agent.agent_account.station_id,
        &agent.key_authorization,
    )?;
    let mut agent_group =
        arkret::ArkretMlsGroup::join_from_verified_welcome_delivery(identity, &welcome, &accepted)?;
    for (http, participant_group, actor) in [
        (
            controller.client.sdk(),
            &mut *group,
            controller.actor.clone(),
        ),
        (
            agent.runtime.sdk(),
            &mut agent_group,
            arkret_wire::ActorId::account(agent.agent_account.clone()),
        ),
    ] {
        let request = arkret::MlsMemberRosterAuthorityReadRequestBody {
            realm_id: realm.clone(),
            effective_scope: scope.clone(),
            mls_group_id: scope.canonical_mls_group_id()?,
            target_commit_event_ref: event.event_id.clone(),
            target_epoch: 1,
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
            participant_group,
            &[page],
            &request,
            &material,
        )
        .map_err(anyhow::Error::msg)?;
    }
    // The original group and exact accepted transition are durably saved before
    // the runtime submits its endpoint's consume receipt.
    let journal = tempfile::tempdir()?;
    let bytes = serde_json::to_vec(&agent_group.export_state_record()?)?;
    let journal_path = journal.path().join("agent-group.json");
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&journal_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    let restored: arkret::MlsGroupStateRecord =
        serde_json::from_slice(&std::fs::read(&journal_path)?)?;
    agent_group = arkret::ArkretMlsGroup::restore_from_state_record(&restored)?;
    let receipt = arkret_models_crypto::RecipientMlsDurableReceipt {
        domain: arkret_wire::NonEmptyString::new(
            arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1,
        )
        .map_err(anyhow::Error::msg)?,
        claim_request_id: claim.claim_request_id,
        keypackage_ref: arkret_wire::NonEmptyString::new(selected.keypackage_ref.clone())
            .map_err(anyhow::Error::msg)?,
        recipient: arkret_models_crypto::RecipientMlsDurableSigner::Agent {
            recipient_agent_id: agent.agent_account.principal_id.clone(),
            recipient_agent_verification_method: agent.verification_method.clone(),
            agent_key_authorize_event_id: agent.key_authorization.clone(),
        },
        recipient_id: agent.agent_account.station_id.clone(),
        realm_id: realm.clone(),
        mls_group_id: scope.canonical_mls_group_id()?,
        mls_epoch: 1,
        welcome_ref: welcome.welcome_id.clone(),
        welcome_digest: welcome.durable_receipt_digest()?,
        durable_at: chrono::Utc::now(),
        signature: arkret_models_crypto::KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(agent.verification_method.to_string())
                .map_err(anyhow::Error::msg)?,
            signature_algorithm: None,
            signature: arkret_wire::Base64UrlString::new("AA").map_err(anyhow::Error::msg)?,
        },
    };
    let receipt = agent_group
        .identity()
        .sign_recipient_mls_durable_receipt(receipt)?;
    let consume = agent_group.identity().signed_key_packages_consume_request(
        arkret_wire::KeypackageClaimId::new(selected.claim_id.clone())?,
        receipt,
    )?;
    if let Some(observer) = observer {
        observer
            .before_consume(
                controller,
                agent,
                group,
                &mut agent_group,
                &accepted,
                &journal_path,
            )
            .await?;
    }
    let signed_digest = arkret_models_crypto::keypackages_consume_request_digest(&consume)?;
    let unsigned = arkret_models_crypto::KeyPackagesConsumeFields {
        claim_id: consume.claim_id.clone(),
        recipient_durable_receipt: consume.recipient_durable_receipt.clone(),
    };
    ensure!(signed_digest != arkret_canonical::canonical_sha256(&unsigned)?);
    let consumed = agent.runtime.sdk().keypackages_consume(&consume).await?;
    ensure!(
        consumed.consume_receipt.request_digest.as_str() == signed_digest,
        "Sidecar consume receipt did not bind the complete signed command"
    );
    let replay = agent.runtime.sdk().keypackages_consume(&consume).await?;
    ensure!(
        arkret_canonical::canonical_json_bytes(&replay)?
            == arkret_canonical::canonical_json_bytes(&consumed)?,
        "Sidecar consume replay replaced its original receipt"
    );
    if let Some(sidecar_id) = sidecar_id {
        let view = controller
            .client
            .sdk()
            .agent_sidecar_get(sidecar_id)
            .await?;
        ensure!(
            view.effective_agent_ids == vec![agent.agent_account.principal_id.clone()],
            "Sidecar did not activate after full-command consume and exact replay: {view:?}"
        );
        let http = agent.runtime.sdk();
        let snapshot = http.realm_state_snapshot_head(realm).await?;
        let stream = arkret_wire::CommitStreamRef::from_scope(scope, Some(realm.clone()))?;
        ensure!(
            snapshot
                .current_state_entries
                .iter()
                .any(|row| matches!(row,
            arkret_wire::CurrentState::Value {
                selector: arkret_wire::CurrentSelector::SidecarContext { .. }, source_stream_ref, ..
            } if source_stream_ref == &stream)),
            "consumed Agent cannot read its private current"
        );
        let original = http
            .realm_state_snapshot_by_ref(realm, &snapshot.snapshot_id)
            .await?;
        ensure!(
            arkret_canonical::canonical_json_bytes(&original)?
                == arkret_canonical::canonical_json_bytes(&snapshot)?,
            "effective Agent by-ref rewrote the original"
        );
        let mut forward = Vec::new();
        for direction in [
            arkret_wire::StreamScanDirection::After(None),
            arkret_wire::StreamScanDirection::Before(None),
        ] {
            let request = arkret_wire::StreamScanRequestBody {
                realm_id: realm.clone(),
                stream_ref: stream.clone(),
                direction,
                limit: 100,
            };
            let page = http.scan_commit_stream(&request).await?;
            page.validate_for_request(&request)?;
            ensure!(
                !page.truncated
                    && page.committed_events.iter().any(|row| row
                        .reducer_input()
                        .is_some_and(|event| event.event_id == accepted.event.event_id)),
                "effective Agent scan lacks its real consumed transition"
            );
            let ids = page
                .committed_events
                .iter()
                .map(|row| row.commit().commit_id.clone())
                .collect::<Vec<_>>();
            if matches!(
                request.direction,
                arkret_wire::StreamScanDirection::After(_)
            ) {
                forward = ids;
            } else {
                ensure!(
                    ids == forward.iter().rev().cloned().collect::<Vec<_>>(),
                    "effective Agent forward/backward scans disagree"
                );
            }
        }
        eprintln!(
            "[2133-effective-agent] actual_openmls_welcome=1 durable_restore=1 signed_consume=1 private_current=1 exact_by_ref=1 bidirectional_scan=1"
        );
    }
    Ok((accepted, agent_group))
}
