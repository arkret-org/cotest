//! Live fixture content preparation. Only authenticated native sources and
//! actual accepted Root backup PUTs qualify the material returned here.

use anyhow::{Context as _, Result, ensure};
use arkret::{ArkretMlsGroup, Event, EventId, EventPayloadExt as _};
use arkret_models_crypto::*;
use ed25519_dalek::Signer as _;

mod recovery_policy;
pub use recovery_policy::{controller_history_custody, ensure_controller_recovery_policy};
mod device;
pub use device::{registered_device_client, seal_device_message};

pub async fn root_context(
    http: &arkret_http_client::Client,
    group: &ArkretMlsGroup,
    reference: &EventId,
) -> Result<ContentRootContext> {
    let source = http
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

#[derive(serde::Serialize, serde::Deserialize)]
struct FrozenContent {
    intent_digest: String,
    material: EventContentMaterial,
    backup: KeyBackup,
}

#[allow(clippy::too_many_arguments)]
pub async fn prepare(
    http: &arkret_http_client::Client,
    directory: &std::path::Path,
    group: &ArkretMlsGroup,
    event: &Event,
    reference: &EventId,
    path: &str,
    content_type: &str,
    plaintext: &[u8],
    author: arkret::crypto::content_history::ContentRootBackupAuthor,
    policy: RecoveryPolicyRef,
    recipient: String,
    public: &[u8],
    custody: Option<(arkret::ActorId, EventId)>,
    signer: &ed25519_dalek::SigningKey,
) -> Result<EventContentMaterial> {
    use std::io::Write as _;
    let source = http
        .own_station_result_client()?
        .context("native content source required")?;
    source.check_session()?;
    ensure!(
        path.starts_with('/') && event.actual_signer() == group.local_actor_id(),
        "content intent differs from actual endpoint"
    );
    ensure!(
        event.actual_signer().as_account_id() == Some(source.session()?.account_id()),
        "content author differs from the authenticated native Account"
    );
    let context = root_context(http, group, reference).await?;
    let root = group.export_content_root(&context)?;
    let root_ref = arkret::crypto::content_history::content_root_ref(&root, &context)?;
    let producer = group.local_content_endpoint()?;
    let outer = EventContentMaterial::outer_event_for(event)?;
    let operation = arkret_canonical::canonical_sha256(&(
        &outer,
        arkret_canonical::canonical_sha256(&event.payload)?,
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
    std::fs::create_dir_all(directory)?;
    let file_path = directory.join(format!("{operation}.json"));
    let frozen: FrozenContent = if file_path.exists() {
        let metadata = std::fs::symlink_metadata(&file_path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "frozen native content must be a regular fixture file"
        );
        serde_json::from_slice(&std::fs::read(&file_path)?)?
    } else {
        let entry = ContentRootBackupEntry {
            item_kind: ContentRootItemKind::ContentEpochRoot,
            secret_id: format!("root_{}", root_ref.as_str().trim_start_matches("sha256:")),
            root_context: context.clone(),
            root_ref: root_ref.clone(),
            root_base64url: root.clone(),
        };
        let backup = arkret::crypto::content_history::ContentRootBackupDraft {
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
            content_key_salt: arkret::crypto::content_history::fresh_content_key_salt()?,
        };
        let key = arkret::crypto::content_history::derive_content_key(&root, &content_context)?;
        let material = EventContentMaterial {
            key_commitment: arkret::crypto::content_history::content_key_commitment(
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
        let frozen = FrozenContent {
            intent_digest: operation.clone(),
            material,
            backup,
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&file_path)?;
        file.write_all(&arkret_canonical::canonical_json_bytes(&frozen)?)?;
        file.sync_all()?;
        #[cfg(unix)]
        std::fs::File::open(directory)?.sync_all()?;
        frozen
    };
    ensure!(
        frozen.intent_digest == operation
            && frozen.material.outer_event == outer
            && frozen.material.content_context.root_context == context
            && frozen.material.content_context.producer == producer
            && frozen.material.content_context.root_ref == root_ref,
        "frozen native content intent changed"
    );
    ensure!(
        frozen.backup.actor_id == event.actor_id
            && frozen.material.protection.backup_refs == [frozen.backup.backup_id.clone()]
            && frozen.material.protection.root_refs == [root_ref.clone()]
            && frozen.backup.contents.len() == 1
            && frozen.backup.contents[0].item_kind == SecretStorageItemKind::ContentEpochRoot
            && frozen.backup.contents[0].root_context.as_ref() == Some(&context)
            && frozen.backup.contents[0].root_ref.as_ref() == Some(&root_ref),
        "frozen native Root backup differs from its complete protection references"
    );
    let key = arkret::crypto::content_history::derive_content_key(
        &root,
        &frozen.material.content_context,
    )?;
    ensure!(
        arkret::crypto::content_history::content_key_commitment(
            &frozen.material.content_context,
            &key
        )? == frozen.material.key_commitment,
        "frozen content key commitment changed"
    );
    source.check_session()?;
    let result = http
        .put_key_backup(&frozen.backup.backup_id, &frozen.backup, &operation)
        .await?;
    ensure!(
        result.backup_id == frozen.backup.backup_id
            && result.ciphertext_digest == frozen.backup.ciphertext_digest,
        "native root PUT acknowledged another object"
    );
    source.check_session()?;
    Ok(frozen.material)
}
