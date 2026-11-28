//! Exercise the replacement through the registered self MLS admission lane.
use arkret_event_draft::EventPayloadExt as _;
use arkret_wire::{
    AuthoritySubmitResponseBody, CommittedEventFullView, Event, MlsCommitSubmission,
};

use super::*;
use crate::scenarios::call_recording_live::material_request;

// The private PCR has no ordinary Realm snapshot. The replacement proposes
// against the exact state frozen by preparation, then advances only on its
// returned originals. PostgreSQL is an independent assertion, never client input.
async fn check_current(database: &str, expected: &arkret_wire::MlsGroupValue) -> Result<()> {
    let key = arkret_canonical::canonical_json_string(&expected.effective_scope)?;
    let actual: Value = query(database, move |db| {
        Ok(db
            .query_one(
                "SELECT value FROM mls_group_current_states WHERE scope_key=$1",
                &[&key],
            )?
            .get(0))
    })
    .await?;
    ensure!(
        expected == &serde_json::from_value::<arkret_wire::MlsGroupValue>(actual)?,
        "prepared client base differs from the native MLS current"
    );
    Ok(())
}

fn successor(
    current: &arkret_wire::MlsGroupValue,
    accepted: &CommittedEventFullView,
) -> Result<arkret_wire::MlsGroupValue> {
    let payload = accepted.event.as_mls_commit()?;
    ensure!(
        payload.base_group_state_ref() == &current.current_mls_commit_event_ref
            && payload.base_epoch() == current.epoch
    );
    Ok(arkret_wire::MlsGroupValue {
        current_mls_commit_event_ref: accepted.event.event_id.clone(),
        epoch: payload.next_epoch(),
        covered_key_access_revision: payload.covers_key_access_revision(),
        public_tree_ref: payload.ratchet_tree_ref().clone(),
        ..current.clone()
    })
}

async fn publish(
    member: &Member,
    base: &Event,
    revision: u64,
    handshake: &MlsCommitEnvelope,
    governance: arkret::MlsGovernanceBindingPayload,
    recovery: ContentRecoveryBinding,
    material: (Vec<u8>, Vec<u8>),
) -> Result<Event> {
    let info = serde_json::from_value(upload(&member.client, &material.0).await?)?;
    let tree = serde_json::from_value(upload(&member.client, &material.1).await?)?;
    let payload = MlsCommitPayload::new(
        base.event_id.clone(),
        revision,
        handshake,
        governance,
        info,
        tree,
    )?
    .with_recovery_binding(recovery)?;
    Ok(private_event(
        member,
        &base.realm_id,
        EventKind::MlsCommit,
        serde_json::to_value(payload)?,
    ))
}

async fn submit(member: &Member, event: &Event) -> Result<CommittedEventFullView> {
    let body = MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: vec![],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7())?,
        recovery_source: None::<arkret_wire::NoRecoverySource>,
    };
    let frozen = arkret_canonical::canonical_json_bytes(&body)?;
    let request = || {
        member
            .client
            .post("/_arkret/self/events")
            .header("content-type", "application/json")
            .body(frozen.clone())
    };
    let first = crate::harness::withhold_station_receipt(request()).await?;
    let second = request().send().await?.error_for_status()?.bytes().await?;
    let extract = |bytes: &[u8]| -> Result<_> {
        let outcome: AuthoritySubmitResponseBody = serde_json::from_slice(bytes)?;
        let AuthoritySubmitResponseBody::Accepted { commit, .. } = outcome else {
            anyhow::bail!("recovery Commit refused")
        };
        commit.validate_content_address()?;
        ensure!(commit.event_ref == event.event_id);
        Ok(commit)
    };
    let first = extract(&first)?;
    ensure!(
        extract(&second)? == first,
        "receipt retry changed the accepted Commit"
    );
    let view = accepted_full_view(&member.client, &event.event_id).await?;
    ensure!(view.commit == first && view.event == *event);
    verify_original(&view, member)?;
    Ok(view)
}

pub(in crate::conformance::recovery_transaction_faults::native) async fn run(
    client: &TestActorClient,
    material: &Material,
    ready: &Value,
    database: &str,
    generation: u64,
    old_message: &Event,
) -> Result<Value> {
    let preparation: ContentRecoveryPreparation =
        serde_json::from_value(ready["preparation"].clone())?;
    let reference = preparation
        .inventory_blob_ref
        .context("missing prepared inventory")?;
    let raw = client
        .get("/_arkret/self/blob/get")
        .query(&[("blob_ref", reference.as_str())])
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let inventory: ContentRecoveryInventory = serde_json::from_slice(&raw)?;
    let digest = arkret_crypto::content_history::recovery_inventory_digest(&inventory)?;
    ensure!(json!(digest) == ready["inventory_digest"]);
    let member = Member::from_client(client.clone(), material.owner.account.clone())?;
    let early_old = refuse_old_message(material, old_message, database).await?;
    eprintln!("old Device before group cleanup: {early_old}");
    let mut results = Vec::new();
    let mut failures = Vec::new();
    for entry in &inventory.entries {
        let observed = crate::harness::heap_future(|| {
            rekey_group(&member, material, &inventory, entry, database, generation)
        })
        .await;
        match observed {
            Ok(result) => results.push(result),
            Err(error) => failures.push(format!(
                "{}: {error:#}",
                if entry.genesis_event_ref == material.event.event_id {
                    "PCR"
                } else {
                    "empty Realm"
                }
            )),
        }
    }
    ensure!(failures.is_empty(), "{}", failures.join("\n"));
    ensure!(results.len() == 2);
    let final_old = refuse_old_message(material, old_message, database).await?;
    ensure!(final_old == early_old);
    Ok(json!({
        "prepared": reference,
        "groups": results,
        "old_device_before_rekey": early_old,
        "old_device_after_rekey": final_old,
    }))
}

async fn rekey_group(
    member: &Member,
    material: &Material,
    inventory: &ContentRecoveryInventory,
    entry: &ContentRecoveryInventoryEntry,
    database: &str,
    generation: u64,
) -> Result<Value> {
    let client = &member.client;
    let base = accepted_full_view(client, &entry.base_group_state_ref).await?;
    verify_original(&base, &material.owner)?;
    let own = client.sdk();
    let genesis = base.event.as_mls_genesis()?;
    ensure!(
        entry.genesis_event_ref == base.event.event_id
            && entry.effective_scope == base.event.scope_ref
    );
    let current = arkret_wire::MlsGroupValue {
        effective_scope: entry.effective_scope.clone(),
        genesis_event_ref: entry.genesis_event_ref.clone(),
        cipher_suite: genesis.cipher_suite,
        current_mls_commit_event_ref: entry.base_group_state_ref.clone(),
        epoch: entry.epoch,
        current_key_access_revision: genesis.governance_binding.key_access_revision(),
        covered_key_access_revision: genesis.governance_binding.key_access_revision(),
        public_tree_ref: genesis.ratchet_tree_ref,
    };
    check_current(database, &current).await?;
    ensure!(
        current.current_mls_commit_event_ref == base.event.event_id && current.epoch == entry.epoch
    );
    let public = own
        .self_mls_group_state_material(&material_request(member, &current, &base)?)
        .await
        .context("replacement reading prepared GroupInfo and ratchet tree")?;
    let binding = arkret::MlsGovernanceBindingPayload::new(
        entry.effective_scope.clone(),
        Some(base.event.event_id.clone()),
        current.epoch,
        current.epoch + 1,
        current.current_key_access_revision,
    )?;
    let recovery = ContentRecoveryBinding {
        replacement: inventory.replacement.clone(),
        authorization_event_ref: inventory.authorization_event_ref.clone(),
        base_group_state_ref: base.event.event_id.clone(),
        expected_epoch: current.epoch,
        inventory_digest: arkret_crypto::content_history::recovery_inventory_digest(inventory)?,
    };
    let candidate = arkret::PreparedMlsRecoveryExternalCommit::prepare(
        member.mls_identity()?,
        &base,
        &public,
        &current,
        &recovery,
        &binding,
    )?;
    let event = publish(
        member,
        &base.event,
        current.current_key_access_revision,
        candidate.commit(),
        binding,
        recovery.clone(),
        candidate.public_group_state_bytes()?,
    )
    .await?;
    let joined = submit(member, &event)
        .await
        .context("External Commit admission and retry")?;
    check_recovery_proof(database, &joined, &inventory.pcr_cut).await?;
    let mut tracker = arkret::MlsPublicGroupTracker::from_external(
        &candidate.public_group_state_bytes()?.0,
        &candidate.public_group_state_bytes()?.1,
        current.effective_scope.canonical_mls_group_id()?.as_str(),
        current.epoch + 1,
    )?;
    let mut bindings = Vec::new();
    let mut remove = Vec::new();
    for leaf in tracker.leaves()? {
        let endpoint =
            if leaf.signature_key.as_str() == inventory.replacement.signature_key_base64url {
                &inventory.replacement
            } else {
                let old = entry
                    .old_leaves
                    .iter()
                    .find(|old| old.endpoint.signature_key_base64url == leaf.signature_key.as_str())
                    .context("unexpected leaf in the two single-owner groups")?;
                remove.push(leaf.leaf_index);
                &old.endpoint
            };
        let arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } = &endpoint.endpoint
        else {
            anyhow::bail!("not a Human Device")
        };
        bindings.push(arkret::MlsVerifiedLeafBinding {
            leaf_index: leaf.leaf_index,
            actor_id: leaf.actor_id,
            endpoint: MlsEndpointIdentity::human_device(
                member.account.principal_id.clone(),
                device_id.clone(),
            ),
            signature_key: leaf.signature_key,
            device_authorize_event_id: Some(endpoint.authorization_event_ref.clone()),
        });
    }
    ensure!(remove.len() == 1 && remove.len() == entry.old_leaves.len());
    let mut group = candidate.install_accepted(&joined, bindings)?;
    let middle = successor(&current, &joined)?;
    check_current(database, &middle).await?;
    ensure!(
        middle.epoch == current.epoch + 1 && middle.current_mls_commit_event_ref == event.event_id
    );
    let binding = arkret::MlsGovernanceBindingPayload::new(
        entry.effective_scope.clone(),
        Some(event.event_id.clone()),
        current.epoch + 1,
        current.epoch + 2,
        current.current_key_access_revision,
    )?;
    let removal =
        group.remove_members_by_leaf_indices_with_governance_binding(&remove, &binding)?;
    let recovery = ContentRecoveryBinding {
        base_group_state_ref: event.event_id.clone(),
        expected_epoch: current.epoch + 1,
        ..recovery
    };
    let post = group.pending_public_group_state_bytes(&removal.commit, &binding)?;
    let cleanup = publish(
        member,
        &event,
        current.current_key_access_revision,
        &removal.commit,
        binding,
        recovery,
        post,
    )
    .await?;
    let final_view = submit(member, &cleanup)
        .await
        .context("Remove Commit admission and retry")?;
    check_recovery_proof(database, &final_view, &inventory.pcr_cut).await?;
    group.install_accepted_commit(&final_view, &middle)?;
    let terminal = publish_root(
        member,
        material,
        &group,
        &entry.genesis_event_ref,
        &inventory.pcr_cut,
        &final_view,
        generation,
        database,
    )
    .await
    .context("persisting and reopening the new epoch root")?;
    tracker.process_public_handshake(&arkret_canonical::base64url_decode(
        removal.commit.commit.as_str(),
    )?)?;
    let leaves = tracker.leaves()?;
    ensure!(
        leaves.len() == 1
            && leaves[0].signature_key.as_str() == inventory.replacement.signature_key_base64url
    );
    let resulting = successor(&middle, &final_view)?;
    check_current(database, &resulting).await?;
    ensure!(
        resulting.epoch == current.epoch + 2
            && resulting.current_mls_commit_event_ref == cleanup.event_id
    );
    let expected = vec![event.event_id.to_string(), cleanup.event_id.to_string()];
    let counts: (i64, i64) = query(database, move |db| {
        let row = db.query_one(
            "SELECT count(DISTINCT e.pk), count(c.commit_id)
             FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk
             WHERE e.envelope->>'event_id'=ANY($1) AND e.state='committed'",
            &[&expected],
        )?;
        Ok((row.get(0), row.get(1)))
    })
    .await?;
    ensure!(counts == (2, 2));
    Ok(json!({
        "group_kind": if entry.genesis_event_ref == material.event.event_id { "personal_pcr" } else { "empty_realm" },
        "scope": entry.effective_scope,
        "base_epoch": current.epoch,
        "join": joined.commit.commit_id,
        "join_epoch": middle.epoch,
        "remove": final_view.commit.commit_id,
        "epoch": resulting.epoch,
        "old_leaves_remaining": terminal["remaining_old_leaf_count"],
        "database_counts": {"events": counts.0, "commits": counts.1},
        "result": terminal,
    }))
}

async fn check_recovery_proof(
    database: &str,
    view: &CommittedEventFullView,
    cut: &arkret_wire::CommittedEventRef,
) -> Result<()> {
    let event_id = view.event.event_id.to_string();
    let auth = cut.commit_id.to_string();
    let (source, fact, authorization): (Vec<u8>, Vec<u8>, Value) = query(database, move |db| {
        let row = db.query_one(
            "SELECT s.recovery_source,s.producer_signer_fact,a.commit_json
            FROM content_recovery_group_commits s JOIN realm_commits a ON a.commit_id=$2
            WHERE s.event_ref=$1",
            &[&event_id, &auth],
        )?;
        Ok((row.get(0), row.get(1), row.get(2)))
    })
    .await?;
    let source: arkret_models_collaboration::content_history::ContentRecoverySource =
        serde_json::from_slice(&source)?;
    let fact: arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact =
        serde_json::from_slice(&fact)?;
    let authorization: arkret_wire::RealmCommit = serde_json::from_value(authorization)?;
    let device = fact
        .as_account_device()
        .context("expected original Human Device")?;
    ensure!(
        device.accepted_at == authorization.committed_at
            && device.key.authorization_ref == *cut
            && device.accepted_at < view.commit.committed_at
    );
    fact.validate_commit_binding(view, view.event.realm_id.digest_suite_code().digest_suite())?;
    source.validate_original_binding(&view.event, view.commit.committed_at, &fact)?;
    arkret_identity::content_scope_cleanup::verify_mls_recovery_source(&source)?;
    Ok(())
}

async fn publish_root(
    member: &Member,
    material: &Material,
    group: &arkret::ArkretMlsGroup,
    genesis_ref: &arkret_wire::EventId,
    pcr_cut: &arkret_wire::CommittedEventRef,
    final_view: &CommittedEventFullView,
    generation: u64,
    database: &str,
) -> Result<Value> {
    let client = &member.client;
    let realm = group.scope().realm_id();
    let declaration = accepted_full_view(client, &realm.event_id()).await?;
    let strategy = declaration
        .event
        .as_realm_create()?
        .object
        .initial_encryption_backup_strategy;
    let context = ContentRootContext {
        effective_scope: group.scope().clone(),
        genesis_event_ref: genesis_ref.clone(),
        epoch: group.epoch(),
        group_state_ref: final_view.event.event_id.clone(),
        cipher_suite: ACTIVE_SUITE.into(),
        encryption_backup_strategy: strategy,
        backup_strategy_ref: declaration.event.event_id,
    };
    let secret = group.export_content_root(&context)?;
    let root = ContentRootBackupEntry {
        item_kind: ContentRootItemKind::ContentEpochRoot,
        secret_id: "replacement_epoch_root".into(),
        root_ref: arkret_crypto::content_history::content_root_ref(&secret, &context)?,
        root_context: context,
        root_base64url: secret,
    };
    let packet = ContentRootBackupDraft {
        backup_id: arkret_identifiers::new_prefixed_uuid7("ak:backup:").parse()?,
        actor_id: member.actor.clone(),
        created_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        expires_at: None,
        author: ContentRootBackupAuthor::Device {
            binding: arkret_crypto::backup::KeyBackupAuthorizationBinding {
                device_id: member.device.clone(),
                verification_method: member.method.clone(),
                signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
                device_authorize_event_id: member.authorize_event_id.clone(),
            },
            source: KeyBackupSourceCommitRef {
                realm_commit_id: pcr_cut.commit_id.clone(),
                device_generation_ref: generation,
            },
        },
        recipient_key_ref: material
            .packet
            .encryption
            .recipient_key_ref
            .clone()
            .context("recipient")?,
        recovery_policy_ref: material
            .packet
            .recovery_policy_ref
            .clone()
            .context("policy")?,
        domain_separation: material.packet.domain_separation.clone(),
        series_id: arkret_identifiers::new_prefixed_uuid7("ak:backup_series:").parse()?,
        series_sequence: 0,
        supersedes: None,
        custody: None,
    }
    .seal(vec![root.clone()], &material.recipient_public, |input| {
        Ok(member.key.sign(input).to_bytes().to_vec())
    })?;
    let ack = client
        .sdk()
        .put_key_backup(
            &packet.backup_id,
            &packet,
            &format!("arkret-key-backup-{}", packet.backup_id),
        )
        .await?;
    ensure!(ack.ciphertext_digest == packet.ciphertext_digest);
    let backup_id = packet.backup_id.to_string();
    let stored: Value = query(database, move |db| {
        Ok(db
            .query_one(
                "SELECT payload FROM key_backups WHERE payload->>'backup_id'=$1",
                &[&backup_id],
            )?
            .get(0))
    })
    .await?;
    let stored: KeyBackup = serde_json::from_value(stored)?;
    ensure!(stored == packet && root.root_ref != material.root.root_ref);
    let bag = arkret_crypto::content_history::open_content_root_backup(
        &stored,
        &material.recipient,
        |bytes, proof| {
            let raw = arkret_canonical::base64url_decode(proof.signature.as_str())
                .map_err(|e| arkret_crypto::Error::Protocol(e.to_string()))?;
            let signature = ed25519_dalek::Signature::from_slice(&raw)
                .map_err(|e| arkret_crypto::Error::Protocol(e.to_string()))?;
            member
                .key
                .verifying_key()
                .verify_strict(bytes, &signature)
                .map_err(|e| arkret_crypto::Error::Protocol(e.to_string()))
        },
    )?;
    ensure!(
        matches!(bag.items.as_slice(),[SecretStorageEntry::ContentRoot(actual)] if actual==&root)
    );
    let winner = final_view.event.event_id.to_string();
    let (terminal, step_count): (Value, i64) = query(database, move |db| {
        let row = db.query_one(
            "SELECT scope_cleanup,
                    (SELECT count(*) FROM content_recovery_group_commits c
                     WHERE c.authorization_event_ref=r.authorization_event_ref AND c.scope_key=r.scope_key)
             FROM content_recovery_group_commits r WHERE event_ref=$1",
            &[&winner],
        )?;
        Ok((row.get(0), row.get(1)))
    }).await?;
    ensure!(
        step_count == 2
            && terminal["winning_commit"]["commit_id"] == json!(final_view.commit.commit_id)
            && terminal["root_refs"] == json!([root.root_ref])
            && terminal["backup_refs"] == json!([packet.backup_id])
            && terminal["remaining_old_leaf_count"] == 0
    );

    Ok(terminal)
}

async fn refuse_old_message(
    material: &Material,
    old_message: &Event,
    database: &str,
) -> Result<Value> {
    let response = material
        .owner
        .client
        .post("/_arkret/self/events")
        .canonical_json(&arkret_wire::EventAdmissionSubmission::new(
            old_message.clone(),
        ))?
        .send()
        .await?;
    let status = response.status();
    let refused: arkret_wire::Problem = response.json().await?;
    ensure!(
        refused.status == status.as_u16()
            && matches!(
                (status, refused.code()),
                (reqwest::StatusCode::FORBIDDEN, "device_unauthorized")
                    | (reqwest::StatusCode::CONFLICT, "device_revoked")
            ),
        "old Device message returned {status}: {}",
        refused.code()
    );
    let id = old_message.event_id.to_string();
    let old_rows: i64 = query(database, move |db| {
        Ok(db
            .query_one(
                "SELECT count(*) FROM canonical_events WHERE envelope->>'event_id'=$1",
                &[&id],
            )?
            .get(0))
    })
    .await?;
    ensure!(old_rows == 0);
    Ok(
        json!({"event":old_message.event_id,"http":status.as_u16(),"reason":refused.code(),"rows":old_rows}),
    )
}
