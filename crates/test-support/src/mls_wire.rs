//! MLS lifecycle steps of the `cotest-wire` oracle.
//!
//! One process runs one step, so every command that continues an endpoint or
//! a group takes and returns its private state as an opaque base64url blob:
//! the identity snapshot of [`ArkretMlsIdentity::export_private_state`] and the
//! group record of [`ArkretMlsGroup::export_state_record`]. The caller never
//! looks inside either blob. Steps and their order follow the live same-Station
//! lifecycle in `src/scenarios/mls_lifecycle_live.rs`
//! (encryption-and-audit.md sections 2.5, 2.6 and 5.1):
//!
//! 1. `mls-keypackages` — an endpoint publishes device-signed KeyPackages whose LeafNode key is its
//!    authorized device key.
//! 2. `mls-genesis` — the creator's epoch-zero group, its public GroupInfo and ratchet tree bytes,
//!    the governance binding and creator leaf authority.
//! 3. `mls-keypackage-claim-request` — the adder's device-signed self claim.
//! 4. `mls-add-member` — one inline Add Commit payload over the claimed KeyPackage and the Welcome
//!    bytes that name the claim.
//! 5. `mls-welcome-delivery` — the Welcome delivery sealed under the method that signed the Commit
//!    Event.
//! 6. `mls-install-commit` — install the accepted Commit and the complete post-transition leaf
//!    bindings.
//! 7. `mls-join-welcome` — the recipient verifies the producer proof and joins from the Welcome
//!    against the accepted Commit.
//! 8. `mls-encrypt-message` — encrypt one Message body at the current epoch.

use anyhow::{Context, Result, bail, ensure};
use arkret::{
    ArkretMlsGroup, ArkretMlsIdentity, ArkretMlsSigner, MlsCommitPayload,
    MlsGovernanceBindingPayload, MlsKeyPackageRecord, MlsVerifiedLeafBinding,
};
use arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority;
use arkret_models_crypto::{
    KeyPackageClaimRecord, KeyPackagesClaimRequestBody, MlsEndpointIdentity, MlsGroupStateRecord,
};
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, CommittedEventFullView, DetachedSignatureContext,
    DeviceId, DidCoreId, DidUrl, Event, EventId, EventKind, KeypackageClaimId, MlsGroupCurrent,
    MlsWelcomeDelivery, MlsWelcomeDeliveryId, MlsWelcomeRecipientEndpoint, RealmId, ScopeRef,
};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Deserialize;
use serde_json::{Value, json};

/// The KeyPackage capability every Arkret content group requires
/// (`keypackage-capability-registry.json`).
const CONTENT_CAPABILITY: &str = "ak.content.v1";
const MESSAGE_ENVELOPE_VERSION: &str = "1.0";
const MESSAGE_CONTENT_TYPE: &str = "application/vnd.arkret.message+json";

/// One human device endpoint: the complete Account Actor, its device, the
/// accepted device verification method and the device key seed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceEndpointInput {
    actor_id: ActorId,
    device_id: DeviceId,
    verification_method: DidUrl,
    signing_seed_b64url: String,
}

impl DeviceEndpointInput {
    fn signing_key(&self) -> Result<SigningKey> {
        signing_key(&self.signing_seed_b64url)
    }

    /// The MLS endpoint whose LeafNode key is the authorized device key and
    /// whose BasicCredential is the complete ActorId.
    fn identity(&self) -> Result<ArkretMlsIdentity> {
        Ok(ArkretMlsIdentity::new_human_device(
            self.actor_id.clone(),
            self.device_id.clone(),
            ArkretMlsSigner::from_ed25519_signing_key(self.signing_key()?),
        )?)
    }
}

/// The accepted authority of one occupied leaf, as the installing client
/// verified it: the device authorization Event and the device public key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeafMemberInput {
    actor_id: ActorId,
    device_id: DeviceId,
    device_authorize_event_id: EventId,
    device_public_key_b64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPackagesInput {
    endpoint: DeviceEndpointInput,
    count: usize,
}

/// `mls-keypackages`: fresh single-use KeyPackages and their device-signed
/// upload request. The private init keys stay in the returned identity state.
pub fn mls_keypackages(input: Value) -> Result<Value> {
    let input: KeyPackagesInput =
        serde_json::from_value(input).context("parse MLS KeyPackages input")?;
    ensure!(input.count > 0, "at least one KeyPackage is required");
    let identity = input.endpoint.identity()?;
    let records = (0..input.count)
        .map(|_| identity.key_package_record())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let upload = identity.signed_key_packages_upload_request(
        &records,
        input.endpoint.verification_method.as_str(),
        None,
    )?;
    Ok(json!({
        "upload_request": upload,
        "identity_state": encode_b64(&identity.export_private_state()?),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisInput {
    endpoint: DeviceEndpointInput,
    device_authorize_event_id: EventId,
    realm_id: RealmId,
    #[serde(default)]
    scope_ref: Option<ScopeRef>,
}

/// `mls-genesis`: the creator's epoch-zero Realm group with itself as the
/// only leaf. The caller uploads both public Blobs and signs the
/// `ak.mls.genesis` Event from the returned members.
pub fn mls_genesis(input: Value) -> Result<Value> {
    let input: GenesisInput = serde_json::from_value(input).context("parse MLS Genesis input")?;
    let scope = input.scope_ref.unwrap_or_else(|| ScopeRef::Realm {
        realm_id: input.realm_id.clone(),
    });
    ensure!(
        scope.realm_id_opt() == Some(&input.realm_id)
            && matches!(scope, ScopeRef::Realm { .. } | ScopeRef::Circle { .. }),
        "MLS Genesis scope must belong to the requested Realm"
    );
    let binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut group = input
        .endpoint
        .identity()?
        .create_group_with_governance_binding(&scope, &binding)?;
    group.install_local_creator_binding(
        input.endpoint.actor_id.clone(),
        Some(input.device_authorize_event_id.clone()),
    )?;
    let verified = group.verified_leaf_bindings()?;
    let [creator] = verified.as_slice() else {
        bail!("MLS Genesis requires the creator's sole verified leaf");
    };
    let MlsEndpointIdentity::HumanDevice { device_id, .. } = &creator.endpoint else {
        bail!("MLS Genesis creator leaf is not a human device");
    };
    ensure!(
        creator.leaf_index == 0
            && creator.actor_id == input.endpoint.actor_id
            && *device_id == input.endpoint.device_id,
        "MLS Genesis creator leaf does not belong to the creating device"
    );
    let creator_leaf_authority = MlsGenesisCreatorLeafAuthority {
        leaf_signature_key_b64u: creator.signature_key.clone(),
        endpoint: MlsWelcomeRecipientEndpoint::Device {
            device_id: device_id.clone(),
        },
        authorization_event_ref: input.device_authorize_event_id,
    };
    creator_leaf_authority.validate()?;
    let (group_info, ratchet_tree) = group.public_group_state_bytes()?;
    Ok(json!({
        "cipher_suite": group.group_ciphersuite_canonical_id()?,
        "governance_binding": binding,
        "creator_leaf_authority": creator_leaf_authority,
        "group_info_b64url": encode_b64(&group_info),
        "ratchet_tree_b64url": encode_b64(&ratchet_tree),
        "group_state": encode_group(&group)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequesterInput {
    account_id: AccountId,
    device_id: DeviceId,
    verification_method: DidUrl,
    device_authorize_event_id: EventId,
    signing_seed_b64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequestInput {
    requester: ClaimRequesterInput,
    target_account_id: AccountId,
    target_device_id: DeviceId,
    realm_id: RealmId,
    #[serde(default)]
    scope_ref: Option<ScopeRef>,
    source_id: DidCoreId,
    destination_id: DidCoreId,
    claim_request_id: String,
    lifetime_seconds: i64,
}

/// `mls-keypackage-claim-request`: a self claim for one of the target
/// device's KeyPackages, signed by the requester's device over the exact
/// request and service binding (device-lifecycle.md section 9).
pub fn mls_keypackage_claim_request(input: Value) -> Result<Value> {
    let input: ClaimRequestInput =
        serde_json::from_value(input).context("parse KeyPackage claim input")?;
    ensure!(
        input.lifetime_seconds > 0,
        "claim lifetime must be positive"
    );
    let scope = input.scope_ref.unwrap_or_else(|| ScopeRef::Realm {
        realm_id: input.realm_id.clone(),
    });
    ensure!(
        scope.realm_id_opt() == Some(&input.realm_id)
            && matches!(scope, ScopeRef::Realm { .. } | ScopeRef::Circle { .. }),
        "MLS claim scope must belong to the requested Realm"
    );
    let signed_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let requester = &input.requester;
    let mut body: KeyPackagesClaimRequestBody = serde_json::from_value(json!({
        "claim_request_id": input.claim_request_id,
        "target_account_id": input.target_account_id,
        "target_device_ids": [input.target_device_id],
        "requester_account_id": requester.account_id,
        "intended_realm_id": input.realm_id,
        "mls_group_id": scope.canonical_mls_group_id()?,
        "claim_purpose": "realm_membership",
        "required_capabilities": [CONTENT_CAPABILITY],
        "expires_at": arkret_canonical::format_timestamp_canonical(
            signed_at + chrono::Duration::seconds(input.lifetime_seconds),
        ),
        "timeout_ms": null,
        "service_binding": {
            "source_id": input.source_id,
            "destination_id": input.destination_id,
        },
        "requester_authorization": {
            "kind": "device",
            "verification_method": requester.verification_method,
            "requester_device_id": requester.device_id,
            "device_authorize_event_id": requester.device_authorize_event_id,
            "signed_at": arkret_canonical::format_timestamp_canonical(signed_at),
            "signature": {
                "kid": requester.verification_method,
                "signature_algorithm": "Ed25519",
                "sig": "AA",
            },
        },
    }))
    .context("build KeyPackage claim request")?;
    let bytes = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &body.unsigned_request(),
        &body.service_binding,
        &body.requester_authorization,
    )?;
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut body.requester_authorization
    else {
        bail!("the claim request was built with the device branch");
    };
    signature.sig = Base64UrlString::new(encode_b64(
        &signing_key(&requester.signing_seed_b64url)?
            .sign(&bytes)
            .to_bytes(),
    ))
    .map_err(anyhow::Error::msg)?;
    Ok(serde_json::to_value(body)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddMemberInput {
    group_state: String,
    claim: KeyPackageClaimRecord,
    base_group_state_ref: EventId,
    key_access_revision: u64,
}

/// `mls-add-member`: one inline Add Commit over the claimed KeyPackage,
/// covering the scope's current key-access revision. The returned group
/// state holds the Commit as pending until `mls-install-commit`.
pub fn mls_add_member(input: Value) -> Result<Value> {
    let input: AddMemberInput = serde_json::from_value(input).context("parse MLS Add input")?;
    let mut group = decode_group(&input.group_state)?;
    let device_id = input
        .claim
        .device_id
        .clone()
        .context("the claimed KeyPackage belongs to a human device")?;
    ensure!(
        input.claim.actor_id.signing_principal_id() == &input.claim.principal_id,
        "the claim record principal differs from its ActorId"
    );
    let record = MlsKeyPackageRecord {
        keypackage_id: format!("ak:mls:kp:{}", fresh_uuid_v7()),
        actor_id: input.claim.actor_id.clone(),
        endpoint: MlsEndpointIdentity::human_device(input.claim.principal_id.clone(), device_id),
        keypackage: input.claim.keypackage.clone(),
        keypackage_ref: arkret_wire::Hash::new(input.claim.keypackage_ref.clone())?,
        cipher_suites: vec![group.group_ciphersuite_canonical_id()?.to_owned()],
        capabilities: input.claim.capabilities.clone(),
        state: arkret_models_crypto::MlsKeyPackageState::Claimed,
        claim_id: Some(input.claim.claim_id.clone()),
        created_at: chrono::Utc::now(),
        expires_at: Some(input.claim.expires_at),
        last_resort: false,
    };
    let base_epoch = group.epoch();
    let binding = MlsGovernanceBindingPayload::new(
        group.scope().clone(),
        Some(input.base_group_state_ref.clone()),
        base_epoch,
        base_epoch.checked_add(1).context("MLS epoch overflow")?,
        input.key_access_revision,
    )?;
    let add = group.add_member_with_governance_binding(&record, &binding)?;
    let payload = MlsCommitPayload::new(
        input.base_group_state_ref,
        input.key_access_revision,
        &add.commit,
        binding,
    )?;
    Ok(json!({
        "commit_payload": payload,
        "welcome": {
            "keypackage_claim_ref": add.welcome.keypackage_claim_ref,
            "ciphertext_b64": add.welcome.ciphertext_b64,
        },
        "group_state": encode_group(&group)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WelcomeDraftInput {
    keypackage_claim_ref: KeypackageClaimId,
    ciphertext_b64: Base64UrlString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WelcomeDeliveryInput {
    commit_event: Event,
    recipient_actor_id: ActorId,
    recipient_device_id: DeviceId,
    welcome: WelcomeDraftInput,
    signing_seed_b64url: String,
}

/// `mls-welcome-delivery`: seal the Welcome for its recipient under the
/// verification method that signed the Commit Event
/// (`ak.mls_welcome_delivery_signature.v1`, encryption-and-audit.md 2.6.1).
pub fn mls_welcome_delivery(input: Value) -> Result<Value> {
    let input: WelcomeDeliveryInput =
        serde_json::from_value(input).context("parse MLS Welcome delivery input")?;
    ensure!(
        input.commit_event.kind == EventKind::MlsCommit,
        "a Welcome is sealed only for an ak.mls.commit Event"
    );
    let method = input
        .commit_event
        .producer_proof
        .as_ref()
        .context("the Commit Event carries its producer proof")?
        .verification_method
        .clone();
    let key = signing_key(&input.signing_seed_b64url)?;
    let mut delivery = MlsWelcomeDelivery {
        welcome_id: MlsWelcomeDeliveryId::new_v7_at(now_ms()),
        realm_id: input.commit_event.realm_id.clone(),
        effective_scope: input.commit_event.scope_ref.clone(),
        commit_event_ref: input.commit_event.event_id.clone(),
        recipient_actor_id: input.recipient_actor_id,
        recipient_endpoint: MlsWelcomeRecipientEndpoint::Device {
            device_id: input.recipient_device_id,
        },
        keypackage_claim_ref: input.welcome.keypackage_claim_ref,
        ciphertext_b64: input.welcome.ciphertext_b64,
        // Replaced below: the proof signs the projection without itself.
        producer_proof: arkret_wire::DetachedObjectSignature {
            context: DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: method.clone(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: chrono::Utc::now(),
            sig: Base64UrlString::new("AA".to_owned()).map_err(anyhow::Error::msg)?,
        },
    };
    delivery.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &welcome_unsigned_projection(&delivery)?,
        DetachedSignatureContext::MlsWelcomeDelivery,
        method,
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        &key,
    )?;
    delivery.validate_shape()?;
    Ok(serde_json::to_value(delivery)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallCommitInput {
    group_state: String,
    accepted_commit: CommittedEventFullView,
    base: MlsGroupCurrent,
    members: Vec<LeafMemberInput>,
}

/// `mls-install-commit`: install the accepted Commit over the exact base
/// current it was built on, then the complete post-transition leaf bindings.
pub fn mls_install_commit(input: Value) -> Result<Value> {
    let input: InstallCommitInput =
        serde_json::from_value(input).context("parse MLS Commit install input")?;
    let mut group = decode_group(&input.group_state)?;
    let epoch = group.install_accepted_commit(&input.accepted_commit, &input.base)?;
    install_leaf_bindings(&mut group, &input.members)?;
    Ok(json!({
        "epoch": epoch,
        "group_state": encode_group(&group)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinWelcomeInput {
    identity_state: String,
    actor_id: ActorId,
    device_id: DeviceId,
    welcome: MlsWelcomeDelivery,
    accepted_commit: CommittedEventFullView,
    producer_public_key_b64url: String,
    members: Vec<LeafMemberInput>,
}

/// `mls-join-welcome`: verify the Welcome producer proof against the method
/// that signed the accepted Commit, then join from it with the identity that
/// generated the claimed KeyPackage.
pub fn mls_join_welcome(input: Value) -> Result<Value> {
    let input: JoinWelcomeInput =
        serde_json::from_value(input).context("parse MLS Welcome join input")?;
    let commit_method = &input
        .accepted_commit
        .event
        .producer_proof
        .as_ref()
        .context("the accepted Commit Event carries its producer proof")?
        .verification_method;
    ensure!(
        input.welcome.producer_proof.verification_method == *commit_method,
        "the Welcome was not sealed by the method that signed its Commit"
    );
    arkret_signatures::detached_object::verify_detached_object_signature(
        &input.welcome.producer_proof,
        &welcome_unsigned_projection(&input.welcome)?,
        DetachedSignatureContext::MlsWelcomeDelivery,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: decode_b64(&input.producer_public_key_b64url)?,
        },
    )?;
    let identity = ArkretMlsIdentity::restore_from_private_state(
        input.actor_id.clone(),
        MlsEndpointIdentity::human_device(
            input.actor_id.signing_principal_id().clone(),
            input.device_id,
        ),
        &decode_b64(&input.identity_state)?,
    )?;
    let mut group = ArkretMlsGroup::join_from_verified_welcome_delivery(
        identity,
        &input.welcome,
        &input.accepted_commit,
    )?;
    install_leaf_bindings(&mut group, &input.members)?;
    Ok(json!({
        "epoch": group.epoch(),
        "group_state": encode_group(&group)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptMessageInput {
    group_state: String,
    group_state_ref: EventId,
    content: Value,
}

/// `mls-encrypt-message`: encrypt one canonical Message body at the group's
/// current epoch and return the `encrypted_content` envelope.
pub fn mls_encrypt_message(input: Value) -> Result<Value> {
    let input: EncryptMessageInput =
        serde_json::from_value(input).context("parse MLS Message encrypt input")?;
    let mut group = decode_group(&input.group_state)?;
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        MESSAGE_ENVELOPE_VERSION,
        MESSAGE_CONTENT_TYPE,
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        group.scope().clone(),
        EventKind::MessageCreate.as_str(),
        group.epoch(),
        input.group_state_ref,
        group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    let plaintext = arkret_canonical::canonical_json_bytes(&input.content)?;
    let sealed = arkret::MessageCrypto::encrypt(&mut group, fresh_uuid_v7(), header, &plaintext)?;
    Ok(json!({
        "encrypted_content": sealed.payload.to_envelope()?,
        "group_state": encode_group(&group)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptSignalInput {
    group_state: String,
    envelope: arkret_wire::SignalEnvelope,
    plaintext: Value,
}

/// Seal with the sender's actual MLS exporter and advance its saved nonce.
pub fn mls_encrypt_signal(input: Value) -> Result<Value> {
    let input: EncryptSignalInput = serde_json::from_value(input)?;
    let mut group = decode_group(&input.group_state)?;
    let bytes = arkret_canonical::canonical_json_bytes(&input.plaintext)?;
    let plaintext = arkret::open_signal_plaintext(&bytes)?;
    plaintext.bind_to_envelope(
        &input.envelope.sender_actor_id,
        input.envelope.sent_at,
        input.envelope.expires_at,
    )?;
    ensure!(
        plaintext.signal_class() == input.envelope.signal_class,
        "Signal class mismatch"
    );
    let sealed = group.encrypt_signal_payload(&input.envelope.aead_binding(), &bytes)?;
    Ok(json!({
        "encrypted_payload": sealed.encrypted_payload,
        "group_state": encode_group(&group)?,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenSignalsInput {
    group_state: String,
    recipient_account_id: AccountId,
    group_state_ref: EventId,
    authority_commit_id: arkret_wire::RealmCommitId,
    parent_realm_authority_commit_id: Option<arkret_wire::RealmCommitId>,
    frames: Vec<arkret_wire::SignalStreamFrame>,
}

/// Open the captured rail with the recipient's independent group and authority.
pub fn mls_open_signals(input: Value) -> Result<Value> {
    let input: OpenSignalsInput = serde_json::from_value(input)?;
    let group = decode_group(&input.group_state)?;
    let mut replay = arkret::AeadNonceReplayTracker::new();
    let mut sequences = std::collections::BTreeMap::<Vec<u8>, u64>::new();
    let mut payloads = Vec::new();
    for frame in input.frames {
        frame.validate()?;
        let arkret_wire::SignalStreamFrame::Signal {
            envelope,
            delivery_authority,
        } = frame
        else {
            bail!("expected a captured Signal frame");
        };
        ensure!(
            delivery_authority.recipient_account_id == input.recipient_account_id,
            "Signal recipient mismatch"
        );
        ensure!(
            envelope.parent_realm_authority_commit_id == input.parent_realm_authority_commit_id,
            "Signal parent cut mismatch"
        );
        let raw: [u8; 32] = decode_b64(delivery_authority.key.public_key_b64u.as_str())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid Signal public key"))?;
        let public_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: raw.to_vec(),
        };
        let bytes = group.open_signal_envelope(
            &envelope,
            arkret::SignalSenderAuthority::AccountDevice {
                public_key: &public_key,
                device_authorize_event_id: &delivery_authority.key.authorization_ref,
            },
            input.group_state_ref.as_str(),
            &input.authority_commit_id,
            &mut replay,
        )?;
        let plaintext = arkret::open_signal_plaintext(&bytes)?;
        plaintext.bind_to_envelope(
            &envelope.sender_actor_id,
            envelope.sent_at,
            envelope.expires_at,
        )?;
        ensure!(
            plaintext.signal_class() == envelope.signal_class,
            "Signal class mismatch"
        );
        let domain = arkret_canonical::canonical_json_bytes(&json!({
            "actor": envelope.sender_actor_id,
            "device": envelope.sender_device_id,
            "scope": envelope.scope_ref,
        }))?;
        let sequence = plaintext.payload_sequence();
        if let Some(previous) = sequences.insert(domain, sequence) {
            ensure!(sequence > previous, "stale Signal payload sequence");
        }
        payloads.push(serde_json::from_slice::<Value>(&bytes)?);
    }
    Ok(json!({ "plaintexts": payloads }))
}

/// Install the every-and-only binding map of the group's occupied leaves.
/// Each leaf must carry exactly the device key its accepted authorization
/// names.
fn install_leaf_bindings(group: &mut ArkretMlsGroup, members: &[LeafMemberInput]) -> Result<()> {
    let mut bindings = Vec::new();
    for leaf in group.active_author_leaves() {
        let arkret::AuthorLeafCredential::Basic { identity } = leaf.credential else {
            bail!("an Arkret content group leaf requires a BasicCredential");
        };
        let actor = arkret_models_crypto::decode_mls_basic_credential_identity(&identity)?;
        let member = members
            .iter()
            .find(|member| member.actor_id == actor)
            .with_context(|| {
                format!("occupied leaf {} names no supplied member", leaf.leaf_index)
            })?;
        ensure!(
            leaf.signature_key == decode_b64(&member.device_public_key_b64url)?,
            "leaf {} does not carry its member's authorized device key",
            leaf.leaf_index
        );
        bindings.push(MlsVerifiedLeafBinding {
            leaf_index: leaf.leaf_index,
            endpoint: MlsEndpointIdentity::human_device(
                actor.signing_principal_id().clone(),
                member.device_id.clone(),
            ),
            actor_id: actor,
            signature_key: Base64UrlString::new(encode_b64(&leaf.signature_key))
                .map_err(anyhow::Error::msg)?,
            device_authorize_event_id: Some(member.device_authorize_event_id.clone()),
        });
    }
    ensure!(
        bindings.len() == members.len(),
        "the supplied members do not match the group's occupied leaves"
    );
    group.install_verified_leaf_bindings(bindings)?;
    Ok(())
}

/// The unsigned projection: the complete Welcome delivery without
/// `producer_proof`.
fn welcome_unsigned_projection(delivery: &MlsWelcomeDelivery) -> Result<Value> {
    let mut unsigned = serde_json::to_value(delivery)?;
    unsigned
        .as_object_mut()
        .context("a Welcome delivery is a JSON object")?
        .remove("producer_proof");
    Ok(unsigned)
}

fn encode_group(group: &ArkretMlsGroup) -> Result<String> {
    Ok(encode_b64(&serde_json::to_vec(
        &group.export_state_record()?,
    )?))
}

fn decode_group(state: &str) -> Result<ArkretMlsGroup> {
    let record: MlsGroupStateRecord =
        serde_json::from_slice(&decode_b64(state)?).context("parse MLS group state record")?;
    Ok(ArkretMlsGroup::restore_from_state_record(&record)?)
}

fn signing_key(seed_b64url: &str) -> Result<SigningKey> {
    let seed: [u8; 32] = decode_b64(seed_b64url)?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("Ed25519 seed must be 32 bytes, got {}", bytes.len())
        })?;
    Ok(SigningKey::from_bytes(&seed))
}

fn encode_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_b64(value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .context("decode base64url")
}

fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or_default()
}

/// A fresh RFC 9562 UUIDv7 in its hyphenated text form.
fn fresh_uuid_v7() -> String {
    MlsWelcomeDeliveryId::new_v7_at(now_ms())
        .as_str()
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT").unwrap()
    }

    fn circle_scope() -> ScopeRef {
        ScopeRef::Circle {
            realm_id: realm(),
            circle_id: arkret_wire::CircleId::new(
                "ak:circle:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT",
            )
            .unwrap(),
        }
    }

    fn endpoint() -> Value {
        json!({
            "actor_id": ActorId::account(AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )),
            "device_id": "ak:device:01904100-0000-7000-8000-000000000006",
            "verification_method": "did:web:alice.example#device",
            "signing_seed_b64url": encode_b64(&[7; 32]),
        })
    }

    #[test]
    fn circle_genesis_is_real_scope_bound_mls_not_parent_realm_state() {
        let authorization = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [3; 32]);
        let input = json!({
            "endpoint": endpoint(), "realm_id": realm(), "scope_ref": circle_scope(),
            "device_authorize_event_id": authorization,
        });
        let output = mls_genesis(input.clone()).unwrap();
        let group = decode_group(output["group_state"].as_str().unwrap()).unwrap();
        assert_eq!(group.scope(), &circle_scope());
        assert_eq!(
            group.group_id(),
            circle_scope().canonical_mls_group_id().unwrap()
        );
        assert_eq!(group.epoch(), 0);
        assert_eq!(group.verified_leaf_bindings().unwrap().len(), 1);
        let (info, tree) = group.public_group_state_bytes().unwrap();
        assert_eq!(
            decode_b64(output["group_info_b64url"].as_str().unwrap()).unwrap(),
            info
        );
        assert_eq!(
            decode_b64(output["ratchet_tree_b64url"].as_str().unwrap()).unwrap(),
            tree
        );

        let mut parent = input.clone();
        parent.as_object_mut().unwrap().remove("scope_ref");
        let parent = mls_genesis(parent).unwrap();
        let parent = decode_group(parent["group_state"].as_str().unwrap()).unwrap();
        assert_ne!(parent.group_id(), group.group_id());
        let mut foreign = input;
        foreign["realm_id"] =
            json!(RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",).unwrap());
        assert!(mls_genesis(foreign).is_err());
    }

    #[test]
    fn circle_claim_signs_exact_group_and_rejects_foreign_scope() {
        use ed25519_dalek::Verifier as _;

        let endpoint = endpoint();
        let authorization = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [3; 32]);
        let input = json!({
            "requester": {
                "account_id": endpoint["actor_id"]["account_id"],
                "device_id": endpoint["device_id"],
                "verification_method": endpoint["verification_method"],
                "device_authorize_event_id": authorization,
                "signing_seed_b64url": endpoint["signing_seed_b64url"],
            },
            "target_account_id": AccountId::new(
                DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
                DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            ),
            "target_device_id": "ak:device:01904100-0000-7000-8000-00000000000e",
            "realm_id": realm(), "scope_ref": circle_scope(),
            "source_id": "ak:did_core:web:station.example",
            "destination_id": "ak:did_core:web:station.example",
            "claim_request_id": encode_b64(&[4; 16]), "lifetime_seconds": 240,
        });
        let request: KeyPackagesClaimRequestBody =
            serde_json::from_value(mls_keypackage_claim_request(input.clone()).unwrap()).unwrap();
        assert_eq!(
            request.mls_group_id,
            circle_scope().canonical_mls_group_id().unwrap()
        );
        let bytes = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
            &request.unsigned_request(),
            &request.service_binding,
            &request.requester_authorization,
        )
        .unwrap();
        let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device {
            signature, ..
        } = &request.requester_authorization
        else {
            panic!("expected signed device claim");
        };
        let signature =
            ed25519_dalek::Signature::from_slice(&decode_b64(signature.sig.as_str()).unwrap())
                .unwrap();
        SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .verify(&bytes, &signature)
            .unwrap();
        let mut foreign = input;
        foreign["realm_id"] =
            json!(RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",).unwrap());
        assert!(mls_keypackage_claim_request(foreign).is_err());
    }

    #[test]
    fn circle_signal_uses_real_aead_and_frozen_dual_cuts() {
        let endpoint = endpoint();
        let authorization = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [3; 32]);
        let genesis = mls_genesis(json!({
            "endpoint": endpoint, "realm_id": realm(), "scope_ref": circle_scope(),
            "device_authorize_event_id": authorization,
        }))
        .unwrap();
        let state_ref = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [4; 32]);
        let scope_cut = arkret_wire::RealmCommitId::from_digest([5; 32]);
        let parent_cut = arkret_wire::RealmCommitId::from_digest([6; 32]);
        let mut envelope: arkret_wire::SignalEnvelope = serde_json::from_value(json!({
            "realm_id": realm(), "scope_ref": circle_scope(),
            "sender_actor_id": endpoint["actor_id"], "sender_device_id": endpoint["device_id"],
            "authority_commit_id": scope_cut, "parent_realm_authority_commit_id": parent_cut,
            "signal_class": "session", "sent_at": "2026-10-05T00:00:00.000Z",
            "expires_at": "2026-10-05T00:00:25.000Z",
            "encrypted_payload": {
                "scheme": "ak.signal_exporter_aead.v1", "key_ref": {"group_state_ref": state_ref},
                "purpose": "ak.signal.v1", "aead_profile": genesis["cipher_suite"],
                "epoch": 0, "nonce": encode_b64(&[0; 12]), "ciphertext": encode_b64(&[0; 16]),
            },
            "proof": {"kind": "detached_jws", "verification_method": format!("did:web:alice.example#{}", endpoint["device_id"].as_str().unwrap()),
                "envelope_digest": format!("sha256:{}", "0".repeat(64)), "jws": ""},
        })).unwrap();
        let plaintext = json!({"kind": "ak.receipt.read", "payload_sequence": 1,
            "actor_id": endpoint["actor_id"], "event_id": state_ref, "read_scope": {"kind": "realm"}});
        let sealed = mls_encrypt_signal(json!({"group_state": genesis["group_state"],
            "envelope": envelope, "plaintext": plaintext}))
        .unwrap();
        envelope.encrypted_payload =
            serde_json::from_value(sealed["encrypted_payload"].clone()).unwrap();
        assert_ne!(
            decode_b64(&envelope.encrypted_payload.ciphertext).unwrap(),
            arkret_canonical::canonical_json_bytes(&plaintext).unwrap()
        );
        let sign = |envelope: &mut arkret_wire::SignalEnvelope| {
            envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
            let header = encode_b64(br#"{"alg":"Ed25519"}"#);
            let input = format!(
                "{header}.{}",
                encode_b64(&envelope.proof_binding_bytes().unwrap())
            );
            let sig = SigningKey::from_bytes(&[7; 32]).sign(input.as_bytes());
            envelope.proof.jws = format!("{header}..{}", encode_b64(&sig.to_bytes()));
        };
        sign(&mut envelope);
        let recipient: AccountId =
            serde_json::from_value(endpoint["actor_id"]["account_id"].clone()).unwrap();
        let frame = |envelope: &arkret_wire::SignalEnvelope| {
            json!({"kind":"signal", "envelope": envelope,
            "delivery_authority": {"recipient_account_id": recipient, "key": {
                "actor": endpoint["actor_id"], "verification_method": envelope.proof.verification_method,
                "public_key_b64u": encode_b64(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes()),
                "authorization_ref": authorization}}})
        };
        let mut input = json!({"group_state": genesis["group_state"], "recipient_account_id": recipient,
            "group_state_ref": state_ref, "authority_commit_id": scope_cut,
            "parent_realm_authority_commit_id": parent_cut, "frames": [frame(&envelope)]});
        assert_eq!(
            mls_open_signals(input.clone()).unwrap()["plaintexts"],
            json!([plaintext])
        );
        input["frames"] = json!([frame(&envelope), frame(&envelope)]);
        assert!(mls_open_signals(input.clone()).is_err());
        // A correctly re-signed mutation still fails AEAD, proving the AAD gate.
        envelope.parent_realm_authority_commit_id =
            Some(arkret_wire::RealmCommitId::from_digest([9; 32]));
        sign(&mut envelope);
        input["parent_realm_authority_commit_id"] =
            json!(envelope.parent_realm_authority_commit_id);
        input["frames"] = json!([frame(&envelope)]);
        assert!(mls_open_signals(input).is_err());
        let next = mls_encrypt_signal(json!({"group_state": sealed["group_state"],
            "envelope": envelope, "plaintext": plaintext}))
        .unwrap();
        assert_ne!(
            sealed["encrypted_payload"]["nonce"],
            next["encrypted_payload"]["nonce"]
        );
    }
}
