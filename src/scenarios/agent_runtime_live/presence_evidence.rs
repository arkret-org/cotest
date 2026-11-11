//! Actual Agent presence over the joined MLS endpoint and live controller rail.

use arkret_models_collaboration::signal_plaintext::{PresencePlaintext, PresenceState};
use arkret_wire::{SignalAeadBinding, SignalClass, SignalEnvelope, SignalKeyRef, SignalProof};

use super::*;

struct VerifiedDecryptor<'a> {
    group: &'a arkret::ArkretMlsGroup,
    state: &'a EventId,
    head: &'a arkret_wire::RealmCommitId,
    replay: std::sync::Mutex<arkret::AeadNonceReplayTracker>,
}

impl garth::signal::SignalDecryptor for VerifiedDecryptor<'_> {
    async fn decrypt(
        &self,
        signal: &SignalEnvelope,
        sender_key: &arkret_wire::StationSigningKey,
    ) -> garth::Result<Vec<u8>> {
        self.group
            .open_signal_envelope_with_station_key(
                signal,
                sender_key,
                self.state.as_str(),
                self.head,
                &mut *self.replay.lock().map_err(|_| {
                    garth::Error::Protocol("nonce tracker mutex poisoned".to_owned())
                })?,
            )
            .map(|bytes| bytes.to_vec())
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

async fn native_session(
    deployment: &coauth_session_evidence::ActualAgentDeployment,
    agent: &AgentRuntimeSession,
    operations: &[&str],
    realm: &RealmId,
) -> Result<(
    TestActorClient,
    arkret_models_collaboration::session_grants::AgentSessionGrantRequestBody,
)> {
    let (credential, request) = coauth_session_evidence::issue_runtime_session_with_scope(
        &deployment.station,
        deployment.coauth.base_url(),
        &deployment.coauth.pg.connect_url,
        &agent.agent_account.principal_id,
        &agent.key_authorization,
        &agent.verification_method,
        &agent.runtime_key,
        operations,
        arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope {
            realm_ids: vec![realm.clone()],
            strand_ids: Vec::new(),
            track_names: Vec::new(),
        },
    )
    .await?;
    let claims = content_session_evidence::observed_issued_claims(&credential)?;
    ensure!(
        claims.scopes.iter().any(|scope| scope == "ak.event.read"),
        "real scoped issuer did not grant Direct read"
    );
    let runtime = deployment.station.client_with_agent_runtime_grant(
        agent.agent_did.as_str(),
        "signal-native-scoped",
        credential,
        agent.runtime_key.clone(),
    )?;
    Ok((runtime, request))
}

pub(super) async fn run_native() -> Result<()> {
    let deployment =
        coauth_session_evidence::actual_agent_deployment("signal-native-agent").await?;
    let station = &deployment.station;
    let controller = &deployment.controller;
    let operations = arkret_schema::agent_runtime_scope::complete_agent_runtime_scope([
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1,
        ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
        ServiceOperationId::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1,
        ServiceOperationId::SELF_MLS_READ_ROSTER_AUTHORITY_V1,
        ServiceOperationId::SELF_MLS_READ_GROUP_STATE_MATERIAL_V1,
        ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_READ_CLAIM_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
        ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
        ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK_V1,
        ServiceOperationId::SELF_SIGNAL_COMMAND_SEND_V1,
        "ak.event.read",
        "ak.message.create",
        "ak.presence.broadcast",
    ])?;
    let operations = operations.iter().map(String::as_str).collect::<Vec<_>>();
    let mut agent = AgentRuntimeSession::establish_observed(
        station,
        AgentSessionIssuer::Coauth {
            base: deployment.coauth.base_url(),
            database_url: &deployment.coauth.pg.connect_url,
        },
        controller,
        &deployment.account,
        "signal-native-runtime",
        requested_scope(&operations)?,
        None,
    )
    .await?;
    let prior =
        content_session_evidence::observed_issued_claims(agent.runtime.session().credential())?;
    ensure!(!prior.scopes.iter().any(|scope| scope == "ak.event.read"));
    let founded = direct_evidence::found(controller, &agent, station).await?;
    let (runtime, request) = native_session(
        &deployment,
        &agent,
        &operations,
        &founded.coordinates.realm_id,
    )
    .await?;
    agent.runtime = runtime;
    agent.issuer_request = Some(request);
    let mut joined =
        direct_mls_evidence::join(station, controller, &agent, &agent.runtime, founded).await?;
    let (runtime, request) =
        native_session(&deployment, &agent, &operations, &joined.realm).await?;
    agent.runtime = runtime;
    agent.issuer_request = Some(request);
    println!(
        "[signal-native-agent-scope] service_only_predecessor_immutable=1 real_scoped_reissue_before_welcome=1 actual_ready_scope_reissue=1"
    );
    let database = station
        .configured_database_url()
        .context("native Station database")?
        .to_owned();
    let expected_actor = ActorId::account(agent.agent_account.clone());
    let expected_owner = ActorId::account(agent.controller_account.clone());
    let agent_id = agent.agent_account.principal_id.to_string();
    let agent_pcr = agent.agent_pcr.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut database = postgres::Client::connect(&database, postgres::NoTls)?;
        let agent_genesis: i64 = database.query_one(
            "SELECT count(*) FROM canonical_events WHERE realm_id=$1 AND kind='ak.realm.create' AND state='committed' AND envelope->'payload'->'object'->>'purpose'='agent_control'",
            &[&agent_pcr],
        )?.get(0);
        ensure!(agent_genesis == 1, "Agent publication has no actual Agent control Realm inception");
        let rows = database.query(
            "SELECT p.owner_actor_id,h.binding FROM mls_key_packages p JOIN content_keypackage_signature_history h ON h.keypackage_id=p.id WHERE p.actor_id=$1 AND p.agent_key_authorize_event_id IS NOT NULL",
            &[&agent_id],
        )?;
        ensure!(!rows.is_empty(), "accepted Agent publication lost its signing history");
        for row in rows {
            let owner: serde_json::Value = row.get(0);
            let binding: serde_json::Value = row.get(1);
            ensure!(owner == serde_json::to_value(&expected_owner)?
                && binding["actor_id"] == serde_json::to_value(&expected_actor)?,
                "Agent signing history confused its encryption Actor with its owner");
        }
        Ok(())
    }).await??;
    let head = crate::scenarios::websocket_live::realm_head(controller, joined.realm.as_str())
        .await?
        .commit_id;
    let mut reader = crate::scenarios::websocket_live::LiveSignalReader::connect(
        station,
        controller,
        joined.realm.as_str(),
    )
    .await?;
    let decryptor = VerifiedDecryptor {
        group: &joined.controller,
        state: &joined.state_ref,
        head: &head,
        replay: Default::default(),
    };
    let mut receiver = garth::signal::SignalReceiver::new();
    let mut previous_nonce = None;
    for sequence in 1..=2 {
        if sequence == 2 {
            let file = tempfile::NamedTempFile::new()?;
            std::fs::write(
                file.path(),
                serde_json::to_vec(&joined.agent.export_state_record()?)?,
            )?;
            file.as_file().sync_all()?;
            joined.agent = arkret::ArkretMlsGroup::restore_from_state_record(
                &serde_json::from_slice(&std::fs::read(file.path())?)?,
            )?;
        }
        let signal = envelope(
            &agent,
            &joined.realm,
            &joined.state_ref,
            &mut joined.agent,
            &head,
            PresenceState::Online,
            sequence,
        )?;
        if let Some(previous) = previous_nonce.replace(signal.encrypted_payload.nonce.clone()) {
            ensure!(previous != signal.encrypted_payload.nonce);
        }
        ensure!(agent.runtime.sdk().signal_send(&signal).await?.accepted);
        let (received, authority) = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                if let Some(arkret_models_collaboration::SignalStreamFrame::Signal {
                    envelope,
                    delivery_authority,
                }) = reader.next_frame().await?
                {
                    ensure!(envelope == signal);
                    break Ok::<_, anyhow::Error>((envelope, delivery_authority));
                }
            }
        })
        .await
        .context("native Agent Signal delivery")??;
        ensure!(
            authority.key.authorization_ref == agent.key_authorization
                && authority.key.verification_method == agent.verification_method
        );
        ensure!(matches!(
            receiver
                .receive(&received, &authority, &decryptor, Utc::now())
                .await?,
            garth::signal::SignalReceiveOutcome::Accepted { .. }
        ));
        ensure!(
            receiver
                .receive(&received, &authority, &decryptor, Utc::now())
                .await
                .is_err()
        );
    }
    reader.finish().await?;
    let principal = controller
        .principal
        .as_ref()
        .context("accepted controller custody")?;
    let method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    let deactivated = sign(
        arkret_event_draft::build_agent_deactivate_intent(
            ActorId::account(agent.agent_account.clone()),
            ActorId::account(agent.controller_account.clone()),
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            agent.delegation.clone(),
            arkret_event_draft::AgentLifecycleState::Active,
            None,
            Utc::now(),
        )?
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &method,
        principal.device_signing_key.to_bytes(),
    )?;
    expect_json(
        controller
            .post(&format!(
                "/_arkret/self/agents/{}/deactivate",
                agent.agent_account.principal_id
            ))
            .json(
                &arkret_models_collaboration::agent_operations::AgentDeactivateRequestBody {
                    reason: None,
                    lifecycle_event: arkret_wire::EventAdmissionSubmission::new(deactivated),
                },
            ),
        StatusCode::OK,
    )
    .await?;
    let terminal = envelope(
        &agent,
        &joined.realm,
        &joined.state_ref,
        &mut joined.agent,
        &head,
        PresenceState::Online,
        3,
    )?;
    let refused = agent
        .runtime
        .post("/_arkret/self/signal")
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(&terminal)?)
        .send()
        .await?;
    let status = refused.status();
    let problem: arkret_wire::Problem = refused.json().await?;
    ensure!(
        matches!(
            status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::PRECONDITION_FAILED
        ),
        "terminal runtime Signal unexpectedly returned {status}: {problem:?}"
    );
    println!(
        "[signal-native-agent] real_coauth_issuer=1 actual_pairing=1 actual_add_welcome=1 native_frames=2 restarted_allocator_continues=1 true_replay_refused=1 native_terminal_runtime_refused=1"
    );
    Ok(())
}

pub(super) async fn positive_direct(
    material: &terminal_evidence::Materials<'_>,
    runtime: &TestActorClient,
    joined: &mut direct_mls_evidence::Joined,
) -> Result<SignalEnvelope> {
    let head =
        crate::scenarios::websocket_live::realm_head(material.controller, joined.realm.as_str())
            .await?
            .commit_id;
    let mut reader = crate::scenarios::websocket_live::LiveSignalReader::connect(
        material.station,
        material.controller,
        joined.realm.as_str(),
    )
    .await?;
    let signal = envelope(
        material.agent,
        &joined.realm,
        &joined.state_ref,
        &mut joined.agent,
        &head,
        PresenceState::Online,
        1,
    )?;
    let outcome = runtime
        .sdk()
        .signal_send(&signal)
        .await
        .context("actual independent Direct Agent presence ingress")?;
    ensure!(outcome.accepted && outcome.envelope_digest == signal.envelope_digest()?);
    let (received, authority) = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(arkret_models_collaboration::SignalStreamFrame::Signal {
                envelope,
                delivery_authority,
            }) = reader.next_frame().await?
            {
                ensure!(envelope == signal);
                break Ok::<_, anyhow::Error>((envelope, delivery_authority));
            }
        }
    })
    .await
    .context("actual Direct Agent presence receiver deadline")??;
    ensure!(
        authority.key.actor == signal.sender_actor_id
            && authority.key.authorization_ref == material.agent.key_authorization
    );
    let decryptor = VerifiedDecryptor {
        group: &joined.controller,
        state: &joined.state_ref,
        head: &head,
        replay: Default::default(),
    };
    let mut receiver = garth::signal::SignalReceiver::new();
    let verified = receiver
        .receive(&received, &authority, &decryptor, Utc::now())
        .await?;
    let mut projection = garth::presence::PresenceProjection::new();
    ensure!(projection.apply_verified(&verified, received.sent_at)?);
    ensure!(
        projection.aggregated(&signal.sender_actor_id, Utc::now())
            == arkret_models_discovery::PresenceStatus::Online
    );
    reader.finish().await?;
    while Utc::now() <= received.expires_at {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    ensure!(
        projection.aggregated(&signal.sender_actor_id, Utc::now())
            == arkret_models_discovery::PresenceStatus::Offline
    );
    let view = material
        .controller
        .sdk()
        .agent_get(material.agent.agent_account.principal_id.as_str())
        .await?;
    ensure!(
        view.agent.lifecycle
            == arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
            && view.agent.readiness.state
                == arkret_models_collaboration::agent_operations::AgentReadinessState::Ready
            && view.agent.readiness.blockers.is_empty()
    );
    let resolved = material.controller.sdk().direct_conversation_resolve(&arkret_models_collaboration::direct_conversation::DirectConversationResolveRequestBody { peer: arkret_models_collaboration::contact_operations::ContactPeer::Agent { actor_id: ActorId::account(material.agent.agent_account.clone()), controller_account_id: material.agent.controller_account.clone() } }).await?;
    ensure!(
        matches!(resolved, arkret_models_collaboration::direct_conversation::DirectConversationResolveResponseBody::Found { coordinates, .. } if coordinates.realm_id == joined.realm)
    );
    println!(
        "[agent-presence-direct] actual_positive_ingress=1 exact_websocket_delivery=1 actual_garth_verification_decryption=1 actual_online_projection=1 real_wallclock_expiry_offline=1 lifecycle_readiness_still_active_ready=1 direct_still_found=1"
    );
    let head =
        crate::scenarios::websocket_live::realm_head(material.controller, joined.realm.as_str())
            .await?
            .commit_id;
    envelope(
        material.agent,
        &joined.realm,
        &joined.state_ref,
        &mut joined.agent,
        &head,
        PresenceState::Online,
        2,
    )
}

fn envelope(
    agent: &AgentRuntimeSession,
    realm: &RealmId,
    state_ref: &EventId,
    group: &mut arkret::ArkretMlsGroup,
    head: &arkret_wire::RealmCommitId,
    state: PresenceState,
    sequence: u64,
) -> Result<SignalEnvelope> {
    let actor = ActorId::account(agent.agent_account.clone());
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let key_ref = SignalKeyRef {
        group_state_ref: state_ref.to_string(),
    };
    let sent_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let expires_at = sent_at + chrono::Duration::seconds(30);
    let binding = SignalAeadBinding {
        realm_id: realm,
        scope_ref: &scope,
        sender_actor_id: &actor,
        sender_device_id: None,
        authority_commit_id: head,
        parent_realm_authority_commit_id: None,
        signal_class: SignalClass::Session,
        sent_at,
        expires_at,
        scheme: arkret_wire::SIGNAL_AEAD_SCHEME,
        key_ref: &key_ref,
        purpose: arkret_wire::SIGNAL_AEAD_PURPOSE,
        aead_profile: crate::scenarios::mls_lifecycle_live::ACTIVE_SUITE,
        epoch: group.epoch(),
    };
    let plaintext = PresencePlaintext::new(sequence, actor.clone(), state, 30000)?;
    let encrypted = group.encrypt_signal_payload(
        &binding,
        &arkret_canonical::canonical_json_bytes(&plaintext)?,
    )?;
    let checkpoint = tempfile::NamedTempFile::new()?;
    std::fs::write(
        checkpoint.path(),
        serde_json::to_vec(&group.export_state_record()?)?,
    )?;
    checkpoint.as_file().sync_all()?;
    let restored = arkret::ArkretMlsGroup::restore_from_state_record(&serde_json::from_slice(
        &std::fs::read(checkpoint.path())?,
    )?)?;
    ensure!(restored.signal_nonce_counter() == group.signal_nonce_counter());
    let mut signal = SignalEnvelope {
        realm_id: realm.clone(),
        scope_ref: scope,
        sender_actor_id: actor,
        sender_device_id: None,
        authority_commit_id: head.clone(),
        parent_realm_authority_commit_id: None,
        signal_class: SignalClass::Session,
        sent_at,
        expires_at,
        encrypted_payload: encrypted.encrypted_payload,
        proof: SignalProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: agent.verification_method.clone(),
            envelope_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            domain: None,
            audience: None,
            jws: String::new(),
        },
    };
    crate::harness::attach_signal_proof(&mut signal, &agent.runtime_key);
    signal.validate_structural()?;
    Ok(signal)
}

pub(super) async fn unmapped_ordinary(
    material: &mut terminal_evidence::Materials<'_>,
    runtime: &TestActorClient,
) -> Result<SignalEnvelope> {
    material
        .controller
        .grant_realm_actions_to(
            material.realm.as_str(),
            material.agent.agent_did.as_str(),
            &["ak.presence.broadcast"],
        )
        .await?;
    let head =
        crate::scenarios::websocket_live::realm_head(material.controller, material.realm.as_str())
            .await?
            .commit_id;
    let before =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            material.database_url,
            true,
        )
        .await?;
    let signal = envelope(
        material.agent,
        material.realm,
        material.state_ref,
        material.group,
        &head,
        PresenceState::Online,
        1,
    )?;
    let response = runtime
        .post("/_arkret/self/signal")
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(&signal)?)
        .send()
        .await?;
    ensure!(response.status() == StatusCode::FORBIDDEN);
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(problem.code() == arkret_wire::ErrorCode::CAPABILITY_DENIED);
    ensure!(
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            material.database_url,
            true
        )
        .await?
            == before
    );
    ensure!(
        runtime
            .get("/_arkret/self/device_messages")
            .send()
            .await?
            .status()
            == StatusCode::OK
    );
    println!(
        "[agent-presence] ordinary_unmapped_content_fail_closed=1 actual_presence_delivery_claim=0 full_footprint_unchanged=1"
    );
    envelope(
        material.agent,
        material.realm,
        material.state_ref,
        material.group,
        &head,
        PresenceState::Online,
        2,
    )
}
