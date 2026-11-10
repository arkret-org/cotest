//! A real registered Device prepares and signs one complete encrypted message.

use anyhow::{Context as _, Result, ensure};
use arkret_models_crypto::*;
use arkret_wire::{ActorId, Event, EventId, EventKind};
use serde_json::{Value, json};

use crate::provisioning::{FoundedPrincipal, FoundingDeviceKey};

#[inline(never)]
fn heap_step<'a, T: 'a, F: std::future::Future<Output = T> + 'a>(
    make: impl FnOnce() -> F,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>> {
    Box::pin(make())
}

/// Restored custody is independently checked against real authority receipts
/// before it can supply a host source. The holder key never signs Events.
#[allow(clippy::too_many_arguments)]
pub async fn registered_device_client(
    http: reqwest::Client,
    principal: &FoundedPrincipal,
    holder: &FoundingDeviceKey,
    station: &str,
    coauth: &str,
    trust_domain: &str,
    ca_pem: &[u8],
) -> Result<arkret_http_client::Client> {
    heap_step(|| principal.validate_restored(coauth, station, trust_domain, holder)).await?;
    let origin = url::Url::parse(station)?;
    let roots = reqwest::Certificate::from_pem_bundle(ca_pem)?;
    ensure!(!roots.is_empty(), "native content transport has no run CA");
    let description = heap_step(|| {
        arkret_http_client::station_connection::fetch_station_description_with_roots(
            &origin, true, &roots,
        )
    })
    .await?;
    let binding = arkret::StationConnectionBinding::from_description(&origin, &description, true)?;
    ensure!(
        binding.service_id == principal.account_id().station_id
            && binding.trust_domain.as_str() == trust_domain,
        "native content Station differs from accepted registration"
    );
    let authority = binding
        .authentication_metadata
        .account_authority
        .as_ref()
        .context("native content Station has no Account Authority")?;
    let authority_origin = url::Url::parse(authority.origin.as_str())?;
    let expected_authority = url::Url::parse(coauth)?;
    ensure!(
        authority_origin.origin() == expected_authority.origin()
            && expected_authority.path() == "/"
            && expected_authority.query().is_none()
            && expected_authority.fragment().is_none(),
        "native content Station declares another Account Authority"
    );
    let initial = &principal
        .accepted_request
        .identity_creation
        .as_ref()
        .context("native content registration intent absent")?
        .initial_session;
    let state = garth::SessionGrantState::from_initial_registration_outcome(
        initial,
        principal.session_grant().clone(),
        chrono::Utc::now(),
    )?;
    let sdk = crate::agent_runtime::controller_transport(
        http,
        station,
        principal.session_grant().session_grant.clone(),
        holder.signing_key(),
    )?;
    let (sdk, _lifetime) = crate::session::bind_registered_host_source(sdk, state, binding)?;
    Ok(sdk)
}

/// The input is the complete, once-authored plaintext Event. Its immutable
/// outer header is fixed before Root preparation, salt, encryption and proof.
pub async fn seal_device_message(
    http: &arkret_http_client::Client,
    principal: &FoundedPrincipal,
    group_state: &str,
    reference: &EventId,
    mut event: Event,
    directory: &std::path::Path,
) -> Result<Value> {
    let source = http
        .own_station_result_client()?
        .context("native content source required")?;
    source.check_session()?;
    let account = principal.account_id();
    ensure!(
        source.session()?.account_id() == account,
        "native content source has another Account"
    );
    let creation = principal
        .accepted_request
        .identity_creation
        .as_ref()
        .context("native content registration intent absent")?;
    let pcr = &creation.pcr_genesis_unit.create().realm_id;
    let device: arkret_wire::DeviceId = principal.device_id.parse()?;
    let method = arkret_wire::DidUrl::new(principal.event_verification_method.clone())
        .map_err(anyhow::Error::msg)?;
    let seed: [u8; 32] = arkret_canonical::base64url_decode(
        principal
            .event_signing_seed_b64url()
            .context("native content Device key absent")?,
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("native content Device key has invalid length"))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let producer = arkret_identity::ProducerVerificationContext {
        actor: ActorId::account(account.clone()),
        verification_method: method.clone(),
        public_key: arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        },
        digest_suite: arkret_canonical::DigestSuite::Sha256,
    };
    arkret_identity::VerifiedProducerEvent::verify(event.clone(), &producer)?;
    let mut group = crate::mls_wire::decode_group(group_state)?;
    ensure!(
        event.kind == EventKind::MessageCreate
            && event.actor_id == producer.actor
            && event.executed_by.is_none()
            && event.scope_ref == *group.scope()
            && group.local_actor_id() == &producer.actor,
        "native message intent differs from the registered Device or MLS scope"
    );
    ensure!(
        matches!(group.local_content_endpoint()?.endpoint,
        arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id } if device_id == device),
        "native message group has another local Device leaf"
    );
    ensure!(
        !event.payload.contains_key("encrypted_content"),
        "native message is already sealed"
    );
    let plaintext = arkret_canonical::canonical_json_bytes(
        event
            .payload
            .get("content")
            .context("native message plaintext absent")?,
    )?;
    let custody = heap_step(|| {
        super::ensure_controller_recovery_policy(
            http,
            account,
            pcr,
            &principal.did,
            &method,
            &source.binding().trust_domain,
            &signing_key,
            &principal.recovery_key,
        )
    })
    .await?;
    let status: RecoveryPolicyStatusView =
        http.get("/_arkret/root/identity/recovery-policy").await?;
    source.check_session()?;
    status.validate_shape()?;
    let policy = status
        .active_policy
        .context("accepted content recovery policy absent")?;
    ensure!(
        policy.account_id == *account
            && policy.policy_id == custody.recovery_policy_ref.policy_id
            && policy.version == custody.recovery_policy_ref.policy_version,
        "content recovery policy changed before freezing the intent"
    );
    let policy_body = policy
        .policy
        .context("accepted content recovery policy original absent")?;
    let recipient = policy_body
        .methods
        .iter()
        .filter_map(|method| match method {
            RecoveryMethod::RecoveryUnlock { keys } => Some(keys),
            _ => None,
        })
        .flatten()
        .find(|key| key.backup_hpke.key_agreement_ref == custody.recipient_key_ref)
        .context("accepted content recovery recipient absent")?;
    let public = arkret::decode_multibase_base58btc(&recipient.backup_hpke.public_key_multibase)?;
    let (codec, prefix) =
        arkret::decode_multicodec_varint(&public).context("backup HPKE multicodec")?;
    ensure!(
        codec == 0xec && public.len() == prefix + 32,
        "content backup recipient is not X25519"
    );
    let keys = http
        .keys_query(&KeysQueryRequestBody {
            device_keys: vec![QueryAccountDeviceSelector {
                account_id: account.clone(),
                device_ids: vec![device.clone()],
            }],
            timeout_ms: None,
        })
        .await?;
    source.check_session()?;
    let anchor = arkret_models_collaboration::events_payloads::key_backup::resolve_controller_backup_trust_anchor(
        &keys, account, &device,
    )?;
    ensure!(
        anchor.authorize_event_id == creation.pcr_genesis_unit.founding_authorize().event_id,
        "content Device authorization changed from its original registered custody"
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
    source.check_session()?;
    ensure!(
        list.active_series.account_id == *account && list.active_series.control_realm_id == *pcr,
        "content backup basis belongs to another Account or PCR"
    );
    let author = arkret::crypto::content_history::ContentRootBackupAuthor::Device {
        binding: arkret::crypto::backup::KeyBackupAuthBinding {
            device_id: device,
            verification_method: method.clone(),
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            device_authorize_event_id: anchor.authorize_event_id,
        },
        source: arkret::KeyBackupSourceCommitRef {
            realm_commit_id: list.active_series.authority_commit_id,
            device_generation_ref: anchor.generation_ref,
        },
    };
    let material = heap_step(|| {
        super::prepare(
            http,
            directory,
            &group,
            &event,
            reference,
            "/payload/encrypted_content",
            crate::mls_wire::MESSAGE_CONTENT_TYPE,
            &plaintext,
            author,
            custody.recovery_policy_ref,
            custody.recipient_key_ref.to_string(),
            &public[prefix..],
            None,
            &signing_key,
        )
    })
    .await?;
    let outer = material.outer_event.clone();
    let mut requested_payload = event.payload.clone();
    requested_payload.remove("content");
    let intent = arkret_canonical::canonical_sha256(&(
        &material,
        &requested_payload,
        arkret_canonical::sha256_digest(&plaintext),
    ))?;
    let signed_path = directory.join(format!("message-{intent}.json"));
    let header = EventContentPreEncryptionHeader::reconstruct(
        crate::mls_wire::MESSAGE_ENVELOPE_VERSION,
        crate::mls_wire::MESSAGE_CONTENT_TYPE,
        arkret_wire::EncryptedPayloadScheme::EpochContentAead,
        event.scope_ref.clone(),
        event.kind.as_str(),
        group.epoch(),
        reference.clone(),
        group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
        material.clone(),
    )?;
    let frozen: garth::FrozenMessageSubmission = if signed_path.exists() {
        let metadata = std::fs::symlink_metadata(&signed_path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "frozen native message must be a regular private fixture file"
        );
        let frozen: garth::FrozenMessageSubmission =
            serde_json::from_slice(&std::fs::read(&signed_path)?)?;
        let signed = &frozen.request().submission.event;
        arkret_identity::VerifiedProducerEvent::verify(signed.clone(), &producer)?;
        let envelope: EncryptedEnvelope = serde_json::from_value(
            signed
                .payload
                .get("encrypted_content")
                .context("frozen native ciphertext absent")?
                .clone(),
        )?;
        let restored = EventContentMaterial::from_original(
            signed,
            &envelope,
            material.content_context.root_context.clone(),
            group.original_content_endpoint(signed)?,
        )?;
        ensure!(
            restored == material,
            "frozen native message changed its complete content intent"
        );
        let mut routed_payload = signed.payload.clone();
        routed_payload.remove("encrypted_content");
        ensure!(
            routed_payload == requested_payload,
            "frozen native message changed its payload routing or metadata"
        );
        let root = group.export_content_root(&material.content_context.root_context)?;
        ensure!(
            arkret::crypto::content_history::open_content(&root, &header, &envelope.ciphertext)?
                == plaintext,
            "frozen native message belongs to another plaintext intent"
        );
        frozen
    } else {
        let encrypted = group.encrypt_payload(header, &plaintext)?;
        event.payload.remove("content");
        event.payload.insert(
            "encrypted_content".into(),
            serde_json::to_value(encrypted.to_envelope()?)?,
        );
        event.producer_proof = None;
        ensure!(
            EventContentMaterial::outer_event_for(&event)? == outer,
            "native message outer header changed after encryption"
        );
        let created_at = event.created_at;
        let authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )?;
        let signer = arkret_signatures::Ed25519PayloadSigner::new(
            signing_key,
            arkret_wire::Did::new(principal.did.clone())?,
            method,
        );
        let frozen = garth::MessageAuthoringSession::from_authored_event(authored)?.sign(
            &signer,
            arkret_signatures::SignEventOptions::new().with_created_at(created_at),
        )?;
        ensure!(
            EventContentMaterial::outer_event_for(&frozen.request().submission.event)? == outer,
            "native message signing changed its frozen outer header"
        );
        use std::io::Write as _;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&signed_path)?;
        file.write_all(&arkret_canonical::canonical_json_bytes(&frozen)?)?;
        file.sync_all()?;
        #[cfg(unix)]
        std::fs::File::open(directory)?.sync_all()?;
        frozen
    };
    source.check_session()?;
    Ok(json!({"event":frozen.request().submission.event,
        "group_state":crate::mls_wire::encode_group(&group)?}))
}
