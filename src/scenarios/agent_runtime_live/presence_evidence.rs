//! Actual Agent presence over the joined MLS endpoint and live controller rail.

use arkret_models_collaboration::signal_plaintext::{PresencePlaintext, PresenceState};
use arkret_wire::{SignalAeadBinding, SignalClass, SignalEnvelope, SignalKeyRef, SignalProof};

use super::*;

fn envelope(
    material: &mut terminal_evidence::Materials<'_>,
    head: &arkret_wire::RealmCommitId,
    state: PresenceState,
    sequence: u64,
) -> Result<SignalEnvelope> {
    let actor = ActorId::account(material.agent.agent_account.clone());
    let scope = ScopeRef::Realm {
        realm_id: material.realm.clone(),
    };
    let key_ref = SignalKeyRef {
        group_state_ref: material.state_ref.to_string(),
    };
    let sent_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let expires_at = sent_at + chrono::Duration::seconds(30);
    let binding = SignalAeadBinding {
        realm_id: material.realm,
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
        epoch: material.group.epoch(),
    };
    let plaintext = PresencePlaintext::new(sequence, actor.clone(), state, 30000)?;
    let encrypted = material.group.encrypt_signal_payload(
        &binding,
        &arkret_canonical::canonical_json_bytes(&plaintext)?,
    )?;
    let checkpoint = tempfile::NamedTempFile::new()?;
    std::fs::write(
        checkpoint.path(),
        serde_json::to_vec(&material.group.export_state_record()?)?,
    )?;
    checkpoint.as_file().sync_all()?;
    let restored = arkret::ArkretMlsGroup::restore_from_state_record(&serde_json::from_slice(
        &std::fs::read(checkpoint.path())?,
    )?)?;
    ensure!(restored.signal_nonce_counter() == material.group.signal_nonce_counter());
    let mut signal = SignalEnvelope {
        realm_id: material.realm.clone(),
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
            verification_method: material.agent.verification_method.clone(),
            envelope_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            domain: None,
            audience: None,
            jws: String::new(),
        },
    };
    crate::harness::attach_signal_proof(&mut signal, &material.agent.runtime_key);
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
    let signal = envelope(material, &head, PresenceState::Online, 1)?;
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
    envelope(material, &head, PresenceState::Online, 2)
}
