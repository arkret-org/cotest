//! Native content preparation for live fixtures. Only actual backup PUT results
//! qualify protection references; local crypto fixtures never enter this path.

use anyhow::{Context as _, Result, ensure};
use arkret::{ArkretMlsGroup, Event, EventId, EventPayloadExt as _};
use arkret_models_crypto::*;
use ed25519_dalek::Signer as _;

use super::{TestActorClient, expect_json};

pub async fn root_context(
    client: &TestActorClient,
    group: &ArkretMlsGroup,
    reference: &EventId,
) -> Result<ContentRootContext> {
    let source = client
        .sdk()
        .own_station_result_client()?
        .context("native content source required")?;
    source.check_session()?;
    let response = source.committed_event_get(reference).await?;
    let arkret::CommittedEventView::Full(current) = response.value()? else {
        anyhow::bail!("content group original withheld");
    };
    group.verify_installed_historical_base(current, reference)?;
    let mut original = current.event.clone();
    let mut seen = std::collections::BTreeSet::new();
    let genesis = loop {
        ensure!(
            seen.insert(original.event_id.clone()) && original.scope_ref == *group.scope(),
            "content lineage cycles or changes scope"
        );
        if original.kind == arkret::EventKind::MlsGenesis {
            break original.event_id;
        }
        ensure!(
            original.kind == arkret::EventKind::MlsCommit,
            "content lineage is not MLS"
        );
        let payload: MlsCommitPayload =
            serde_json::from_value(serde_json::to_value(&original.payload)?)?;
        let previous = source
            .committed_event_get(payload.base_group_state_ref())
            .await?;
        let arkret::CommittedEventView::Full(previous) = previous.value()? else {
            anyhow::bail!("content lineage original withheld");
        };
        original = previous.event.clone();
    };
    let realm = group.scope().realm_id();
    let create_ref = EventId::from_digest(
        realm.digest_suite_code().digest_suite(),
        realm.digest_bytes(),
    );
    let create = source.committed_event_get(&create_ref).await?;
    let arkret::CommittedEventView::Full(create) = create.value()? else {
        anyhow::bail!("original content strategy withheld");
    };
    let strategy = create.event.as_realm_create()?;
    let context = ContentRootContext {
        effective_scope: group.scope().clone(),
        genesis_event_ref: genesis,
        epoch: group.epoch(),
        group_state_ref: reference.clone(),
        cipher_suite: group.group_ciphersuite_canonical_id()?.to_owned(),
        encryption_backup_strategy: strategy.object.initial_encryption_backup_strategy,
        backup_strategy_ref: create.event.event_id.clone(),
    };
    context.validate()?;
    source.check_session()?;
    Ok(context)
}

pub async fn original_material(
    client: &TestActorClient,
    group: &ArkretMlsGroup,
    event: &Event,
    envelope: &EncryptedEnvelope,
) -> Result<EventContentMaterial> {
    let context =
        root_context(client, group, envelope.encryption_context.group_state_ref()).await?;
    Ok(EventContentMaterial::from_original(
        event,
        envelope,
        context,
        group.original_content_endpoint(event)?,
    )?)
}

pub async fn prepare_device(
    client: &TestActorClient,
    group: &ArkretMlsGroup,
    event: &Event,
    reference: &EventId,
    path: &str,
    content_type: &str,
    plaintext: &[u8],
) -> Result<EventContentMaterial> {
    let principal = client
        .principal
        .as_ref()
        .context("native Device signing custody required")?;
    let account = arkret::AccountId::new(principal.core_id.clone(), client.service_id().parse()?);
    ensure!(
        event.actor_id == arkret::ActorId::account(account.clone()) && event.executed_by.is_none(),
        "Device fixture needs explicit Agent custody for cross-subject content"
    );
    ensure!(
        matches!(group.local_content_endpoint()?.endpoint,
        arkret::MlsWelcomeRecipientEndpoint::Device { device_id } if device_id == principal.device_id),
        "content requires this exact Device's installed MLS leaf"
    );
    let http = client.sdk();
    let source = http
        .own_station_result_client()?
        .context("native Device session required")?;
    let method = arkret::DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    let custody = super::heap_future(|| {
        crate::scenarios::agent_runtime_live::ensure_controller_recovery_policy(
            client,
            &account,
            principal,
            &method,
            &source.binding().trust_domain,
        )
    })
    .await?;
    let status: RecoveryPolicyStatusView = serde_json::from_value(
        expect_json(
            client.get("/_arkret/root/identity/recovery-policy"),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    let policy = status
        .active_policy
        .context("accepted backup policy absent")?;
    ensure!(
        policy.account_id == account
            && policy.policy_id == custody.recovery_policy_ref.policy_id
            && policy.version == custody.recovery_policy_ref.policy_version,
        "backup policy changed"
    );
    let body = policy
        .policy
        .context("accepted backup policy original absent")?;
    let recipient = body
        .methods
        .iter()
        .filter_map(|m| match m {
            RecoveryMethod::RecoveryUnlock { keys } => Some(keys),
            _ => None,
        })
        .flatten()
        .find(|k| k.backup_hpke.key_agreement_ref == custody.recipient_key_ref)
        .context("accepted backup recipient absent")?;
    let public = arkret::decode_multibase_base58btc(&recipient.backup_hpke.public_key_multibase)?;
    let (codec, prefix) =
        arkret::decode_multicodec_varint(&public).context("backup HPKE multicodec")?;
    ensure!(
        codec == 0xec && public.len() == prefix + 32,
        "backup recipient is not X25519"
    );
    let keys = http
        .keys_query(&KeysQueryRequestBody {
            device_keys: vec![QueryAccountDeviceSelector {
                account_id: account.clone(),
                device_ids: vec![principal.device_id.clone()],
            }],
            timeout_ms: None,
        })
        .await?;
    let anchor = arkret_models_collaboration::events_payloads::key_backup::resolve_controller_backup_trust_anchor(
        &keys, &account, &principal.device_id,
    )?;
    ensure!(
        anchor.authorize_event_id == principal.founding_authorize_event_id,
        "backup Device authorization changed"
    );
    let list = http
        .list_key_backups(&KeyBackupsListQuery {
            agent_id: None,
            series_id: None,
            backup_kind: None,
            cursor: None,
            limit: Some(1),
        })
        .await?;
    ensure!(
        list.active_series.account_id == account
            && list.active_series.control_realm_id == principal.pcr_realm_id,
        "backup native basis belongs to another Account"
    );
    let author = arkret_crypto::content_history::ContentRootBackupAuthor::Device {
        binding: arkret_crypto::backup::KeyBackupAuthBinding {
            device_id: principal.device_id.clone(),
            verification_method: method,
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            device_authorize_event_id: anchor.authorize_event_id,
        },
        source: arkret::KeyBackupSourceCommitRef {
            realm_commit_id: list.active_series.authority_commit_id,
            device_generation_ref: anchor.generation_ref,
        },
    };
    let result = super::heap_future(|| {
        prepare(
            client,
            group,
            event,
            reference,
            path,
            content_type,
            plaintext,
            author,
            custody.recovery_policy_ref,
            custody.recipient_key_ref.to_string(),
            &public[prefix..],
            None,
            &principal.device_signing_key,
        )
    })
    .await?;
    source.check_session()?;
    Ok(result)
}

pub async fn prepare_agent(
    agent: &crate::scenarios::agent_runtime_live::AgentRuntimeSession,
    group: &ArkretMlsGroup,
    event: &Event,
    reference: &EventId,
    path: &str,
    content_type: &str,
    plaintext: &[u8],
) -> Result<EventContentMaterial> {
    ensure!(
        event.actor_id == arkret::ActorId::account(agent.agent_account.clone())
            && event.executed_by.is_none(),
        "Agent content signer mismatch"
    );
    ensure!(
        matches!(group.local_content_endpoint()?.endpoint,
        arkret::MlsWelcomeRecipientEndpoint::AgentRuntime { verification_method }
            if verification_method == agent.verification_method),
        "content requires this exact Agent runtime's installed MLS leaf"
    );
    let author = arkret_crypto::content_history::ContentRootBackupAuthor::Agent {
        verification_method: agent.verification_method.clone(),
        authorization_event_ref: agent.key_authorization.clone(),
    };
    prepare(
        &agent.runtime,
        group,
        event,
        reference,
        path,
        content_type,
        plaintext,
        author,
        agent.history_custody.recovery_policy_ref.clone(),
        agent.history_custody.recipient_key_ref.to_string(),
        &agent.history_recipient_public,
        Some((
            agent.history_custody.custodian_actor_id.clone(),
            agent.custody_authorization.clone(),
        )),
        &agent.runtime_key,
    )
    .await
}

pub async fn seal_device_message(
    client: &TestActorClient,
    group: &mut ArkretMlsGroup,
    reference: &EventId,
    mut original: Event,
) -> Result<(Event, EncryptedPayload)> {
    let plaintext = arkret_canonical::canonical_json_bytes(
        original
            .payload
            .get("content")
            .context("message plaintext absent")?,
    )?;
    let material = prepare_device(
        client,
        group,
        &original,
        reference,
        "/payload/encrypted_content",
        "application/vnd.arkret.message+json",
        &plaintext,
    )
    .await?;
    let sealed = seal_message(group, &mut original, reference, &plaintext, material)?;
    let key = &client
        .principal
        .as_ref()
        .context("Device signer absent")?
        .device_signing_key;
    super::refresh_typed_event_proof_with_signing_seed(&mut original, key.to_bytes())?;
    Ok((original, sealed))
}

pub async fn seal_agent_message(
    agent: &crate::scenarios::agent_runtime_live::AgentRuntimeSession,
    group: &mut ArkretMlsGroup,
    reference: &EventId,
    mut original: Event,
) -> Result<(Event, EncryptedPayload)> {
    let plaintext = arkret_canonical::canonical_json_bytes(
        original
            .payload
            .get("content")
            .context("message plaintext absent")?,
    )?;
    let material = prepare_agent(
        agent,
        group,
        &original,
        reference,
        "/payload/encrypted_content",
        "application/vnd.arkret.message+json",
        &plaintext,
    )
    .await?;
    let sealed = seal_message(group, &mut original, reference, &plaintext, material)?;
    super::refresh_typed_event_proof_with_signing_seed(
        &mut original,
        agent.runtime_key.to_bytes(),
    )?;
    Ok((original, sealed))
}

fn seal_message(
    group: &mut ArkretMlsGroup,
    original: &mut Event,
    reference: &EventId,
    plaintext: &[u8],
    material: EventContentMaterial,
) -> Result<EncryptedPayload> {
    let header = EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        arkret::EncryptedPayloadScheme::EpochContentAead,
        original.scope_ref.clone(),
        original.kind.as_str(),
        group.epoch(),
        reference.clone(),
        group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
        material,
    )?;
    let encrypted = group.encrypt_payload(header, plaintext)?;
    original.payload.remove("content");
    original.payload.insert(
        "encrypted_content".into(),
        serde_json::to_value(encrypted.to_envelope()?)?,
    );
    Ok(encrypted)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FrozenContent {
    material: EventContentMaterial,
    backup: KeyBackup,
}

#[allow(clippy::too_many_arguments)]
async fn prepare(
    client: &TestActorClient,
    group: &ArkretMlsGroup,
    event: &Event,
    reference: &EventId,
    path: &str,
    content_type: &str,
    plaintext: &[u8],
    author: arkret_crypto::content_history::ContentRootBackupAuthor,
    policy: RecoveryPolicyRef,
    recipient: String,
    public: &[u8],
    custody: Option<(arkret::ActorId, EventId)>,
    signer: &ed25519_dalek::SigningKey,
) -> Result<EventContentMaterial> {
    use std::io::Write as _;
    ensure!(
        path.starts_with('/') && event.actual_signer() == group.local_actor_id(),
        "content intent differs from actual endpoint"
    );
    let context = root_context(client, group, reference).await?;
    let root = group.export_content_root(&context)?;
    let root_ref = arkret_crypto::content_history::content_root_ref(&root, &context)?;
    let producer = group.local_content_endpoint()?;
    let outer = EventContentMaterial::outer_event_for(event)?;
    let operation = arkret_canonical::canonical_sha256(&(
        &outer,
        path,
        content_type,
        &root_ref,
        &producer,
        arkret_canonical::sha256_digest(plaintext),
        &policy,
        &recipient,
        public,
        &custody,
    ))?;
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts/native-content-intents");
    std::fs::create_dir_all(&directory)?;
    let file_path = directory.join(format!("{operation}.json"));
    let frozen: FrozenContent = if file_path.exists() {
        serde_json::from_slice(&std::fs::read(&file_path)?)?
    } else {
        let entry = ContentRootBackupEntry {
            item_kind: ContentRootItemKind::ContentEpochRoot,
            secret_id: format!("root_{}", root_ref.as_str().trim_start_matches("sha256:")),
            root_context: context.clone(),
            root_ref: root_ref.clone(),
            root_base64url: root.clone(),
        };
        let backup = arkret_crypto::content_history::ContentRootBackupDraft {
            backup_id: garth::mls::backup_series::fresh_backup_id()?,
            actor_id: event.actor_id.clone(),
            created_at: arkret::canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            expires_at: None,
            author,
            recipient_key_ref: recipient,
            recovery_policy_ref: policy,
            domain_separation: KeyBackupDomainSeparation {
                subdomain: "content_epoch_root".into(),
                aead_aad_extensions: Default::default(),
            },
            series_id: arkret::BackupSeriesId::new(arkret::new_prefixed_uuid7(
                "ak:backup_series:",
            ))?,
            series_sequence: 0,
            supersedes: None,
            custody,
        }
        .seal(vec![entry], public, |bytes| {
            Ok(signer.sign(bytes).to_bytes().to_vec())
        })?;
        let content_context = ContentContext {
            root_context: context.clone(),
            root_ref: root_ref.clone(),
            purpose: ContentPurpose::EventBody,
            encryption_scheme: arkret::EncryptedPayloadScheme::EpochContentAead,
            encryption_algorithm: ContentEncryptionAlgorithm::Aes128Gcm,
            producer: producer.clone(),
            content_key_salt: arkret_crypto::content_history::fresh_content_key_salt()?,
        };
        let key = arkret_crypto::content_history::derive_content_key(&root, &content_context)?;
        let material = EventContentMaterial {
            key_commitment: arkret_crypto::content_history::content_key_commitment(
                &content_context,
                &key,
            )?,
            content_context,
            outer_event: outer.clone(),
            protection: ContentProtection {
                root_refs: vec![root_ref.clone()],
                blob_refs: vec![],
                backup_refs: vec![backup.backup_id.clone()],
            },
        };
        let frozen = FrozenContent { material, backup };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_path)?;
        file.write_all(&arkret_canonical::canonical_json_bytes(&frozen)?)?;
        file.sync_all()?;
        frozen
    };
    ensure!(
        frozen.material.outer_event == outer
            && frozen.material.content_context.root_context == context
            && frozen.material.content_context.producer == producer
            && frozen.material.content_context.root_ref == root_ref,
        "frozen native content intent changed"
    );
    let key = arkret_crypto::content_history::derive_content_key(
        &root,
        &frozen.material.content_context,
    )?;
    ensure!(
        arkret_crypto::content_history::content_key_commitment(
            &frozen.material.content_context,
            &key
        )? == frozen.material.key_commitment,
        "frozen content key commitment changed"
    );
    let result = client
        .sdk()
        .put_key_backup(&frozen.backup.backup_id, &frozen.backup, &operation)
        .await?;
    ensure!(
        result.backup_id == frozen.backup.backup_id
            && result.ciphertext_digest == frozen.backup.ciphertext_digest,
        "native root PUT acknowledged another object"
    );
    Ok(frozen.material)
}
