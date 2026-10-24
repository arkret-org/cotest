//! Actual Agent presence over the joined MLS endpoint and live controller rail.

use arkret_models_collaboration::signal_plaintext::{PresencePlaintext, PresenceState};
use arkret_wire::{SignalAeadBinding, SignalClass, SignalEnvelope, SignalKeyRef, SignalProof};

use super::*;

struct VerifiedDecryptor<'a> {
    group: &'a arkret::ArkretMlsGroup,
    agent: &'a AgentRuntimeSession,
    state: &'a EventId,
    head: &'a arkret_wire::RealmCommitId,
    public: arkret_signatures::PublicKeyMaterial,
    replay: std::sync::Mutex<arkret::AeadNonceReplayTracker>,
}

impl garth::signal::SignalDecryptor for VerifiedDecryptor<'_> {
    async fn decrypt(&self, signal: &SignalEnvelope) -> garth::Result<Vec<u8>> {
        self.group
            .open_signal_envelope(
                signal,
                arkret::SignalSenderAuthority::Agent {
                    public_key: &self.public,
                    verification_method: &self.agent.verification_method,
                    agent_key_authorize_event_id: &self.agent.key_authorization,
                },
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
        agent: material.agent,
        state: &joined.state_ref,
        head: &head,
        public: arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: arkret_canonical::base64url_decode(authority.key.public_key_base64url.as_str())?,
        },
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
