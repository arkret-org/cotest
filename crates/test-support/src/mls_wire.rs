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
}

/// `mls-genesis`: the creator's epoch-zero Realm group with itself as the
/// only leaf. The caller uploads both public Blobs and signs the
/// `ak.mls.genesis` Event from the returned members.
pub fn mls_genesis(input: Value) -> Result<Value> {
    let input: GenesisInput = serde_json::from_value(input).context("parse MLS Genesis input")?;
    let scope = ScopeRef::Realm {
        realm_id: input.realm_id.clone(),
    };
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
    let scope = ScopeRef::Realm {
        realm_id: input.realm_id.clone(),
    };
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
