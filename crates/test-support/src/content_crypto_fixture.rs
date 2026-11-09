//! Local MLS/AEAD composition fixtures only. The backup selector below is not
//! a native PUT receipt, an authorization proof, or a recoverable server cut.

use anyhow::Result;
use arkret::{ArkretMlsGroup, Event, EventId};
use arkret_models_crypto::{
    ContentContext, ContentEncryptionAlgorithm, ContentProtection, ContentPurpose,
    ContentRootContext, EventContentMaterial,
};

pub fn material(
    group: &ArkretMlsGroup,
    original: &Event,
    genesis: &EventId,
    reference: &EventId,
) -> Result<EventContentMaterial> {
    let root_context = ContentRootContext {
        effective_scope: group.scope().clone(),
        genesis_event_ref: genesis.clone(),
        epoch: group.epoch(),
        group_state_ref: reference.clone(),
        cipher_suite: group.group_ciphersuite_canonical_id()?.to_owned(),
        encryption_backup_strategy: arkret::EncryptionBackupStrategy::EpochContentRoots,
        backup_strategy_ref: EventId::from_digest(
            group.scope().realm_id().digest_suite_code().digest_suite(),
            group.scope().realm_id().digest_bytes(),
        ),
    };
    let root = group.export_content_root(&root_context)?;
    let root_ref = arkret::crypto::content_history::content_root_ref(&root, &root_context)?;
    let context = ContentContext {
        root_context,
        root_ref: root_ref.clone(),
        purpose: ContentPurpose::EventBody,
        encryption_scheme: arkret::EncryptedPayloadScheme::EpochContentAead,
        encryption_algorithm: ContentEncryptionAlgorithm::Aes128Gcm,
        producer: group.local_content_endpoint()?,
        content_key_salt: arkret::crypto::content_history::fresh_content_key_salt()?,
    };
    let key = arkret::crypto::content_history::derive_content_key(&root, &context)?;
    Ok(EventContentMaterial {
        key_commitment: arkret::crypto::content_history::content_key_commitment(&context, &key)?,
        outer_event: EventContentMaterial::outer_event_for(original)?,
        protection: ContentProtection {
            root_refs: vec![root_ref],
            blob_refs: vec![],
            backup_refs: vec![arkret::BackupId::new(arkret::new_prefixed_uuid7(
                "ak:backup:",
            ))?],
        },
        content_context: context,
    })
}

pub fn pending_public_refs(
    group: &ArkretMlsGroup,
    commit: &arkret::MlsCommitEnvelope,
    binding: &arkret::MlsGovernanceBindingPayload,
) -> Result<(arkret::BlobRef, arkret::BlobRef)> {
    let (info, tree) = group.pending_public_group_state_bytes(commit, binding)?;
    let reference = |bytes: &[u8]| {
        arkret::BlobRef::new(format!(
            "ak:blob:{}",
            arkret::canonical::sha256_digest(bytes)
        ))
    };
    Ok((reference(&info)?, reference(&tree)?))
}
